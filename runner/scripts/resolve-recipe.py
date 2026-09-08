#!/usr/bin/env python3
"""Resolve a build recipe + stage manifests into make variables.

Picks sources by asking the selected RECIPE which ENTRY stage to use for the
target's kernel flavour.

It is also the RUN-time selector.  `--format shell` emits the same recipe's
ENTRY stage as a runner contract -- the "foreign chain", an opaque process
behind a declared {invoke, markers, exit-code map, provides} contract -- so
`./pixel-ksu-root --recipe X` and `make RECIPE=X` resolve the identical
stage from the identical files and cannot drift.

Usage:
    runner/scripts/resolve-recipe.py --target <codename-build> [--recipe ghostlock]
                              [--format make|json|shell] [--build-tag STR]

Exit codes:  0 ok, 2 a build-time gate failed (named ARCH-G* error on stderr).

Gates -- every one fails the BUILD, so an invalid composition can never reach a
phone:

    ARCH-G0-RECIPE     unknown recipe
    ARCH-G0-STAGE      recipe names a stage id with no runner/stages/<id>/stage.toml
    ARCH-G0-TARGET     unknown target (no cves/targets/<t>/)
    ARCH-G0-TARGETSET  stage restricted to a target list, target not in it
    ARCH-G0-SCHEMA     manifest/recipe schema or required key missing
    ARCH-G0-INVOKE     --format shell, but the entry declares no runnable
                       {invoke, markers} contract, or declares one whose
                       command template is not satisfiable by the runner
    ARCH-G1-KMI        entry's kernel flavour does not match the target's
    ARCH-G3-FACTS      a required target fact is absent from the target header
    ARCH-G8-WRITER     two selected stages claim the same output artifact
    ARCH-G9-XSRC       data/targets.json and the target header disagree about
                       the target's kernel flavour
"""

import argparse
import json
import os
import re
import sys
import tomllib

RUNNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # runner/
ROOT = os.path.dirname(RUNNER)                                        # repo root
EXPLOIT = os.path.join(ROOT, "cves")        # make's cwd
STAGES = os.path.join(RUNNER, "stages")
RECIPES = os.path.join(RUNNER, "recipes")
TARGETS_JSON = os.path.join(ROOT, "data", "targets.json")

# Facts that, present together in a target.h, prove it is an android14-6.1
# header, and whose absence proves android15-6.6.  Verified across all 19
# committed headers: present in all 15 six-one, absent from all 4 six-six.
# This is G9's second source: the 19 committed target.h are kept precisely so a
# generated fact set can be cross-checked against them.
KMI_MARKERS = {
    "android14-6.1": ["MM_STRUCT_SZ", "KMALLOC_CGROUP_TYPE", "KMALLOC_CACHE_TYPES",
                      "KMALLOC_PIPE_INDEX", "PSELECT_WAITER_WORD_SHIFT",
                      "MAIN_TCP_ROUTE_DEFAULT", "MAIN_TCP_PAYLOAD_DEFAULT"],
}

DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)")

# Output extension implied by the linkage form.
FORM_EXT = {"preload-so": ".so", "static-exe": "", "static-pie": ""}

# Recognised manifest keys.  A bare key written after a [table] header silently
# becomes a member of that table; an unrecognised key is a build error.
STAGE_KEYS = {"schema", "kind", "id", "cve", "kmi", "composed", "status",
              "targets", "build", "facts", "properties", "tunables",
              # The foreign-chain runner contract.
              "invoke", "markers", "exit_map", "provides", "setup"}
# A setup step runs on the device before the entry, once per shot, in declared
# order. Two kinds: {reboot = true} boots to a fresh state, {command = "..."}
# runs a device command (needs_root / once_per_boot optional). A stage that
# declares none inherits the runner's default, a single reboot step.
SETUP_KEYS = {"reboot", "command", "needs_root", "once_per_boot", "description"}
INVOKE_KEYS = {"kind", "artifact_source", "artifact", "dest", "mode", "command",
               "accepts_base", "needs_root"}
MARKER_KEYS = {"pass", "gate_fail", "restore_pass", "restore_bad", "heartbeat",
               "diag", "diag_count"}
PROVIDES_KEYS = {"caps", "field", "label"}

# The two invocation shapes of 2.6, and the placeholders each may use.  The
# runner substitutes exactly these; anything else in a command template is a
# build/run error rather than a broken command line delivered to a phone.
#
#   helper-preload   a .so dlopen'ed by `cve-helper --run-payload`  (GhostLock)
#   device-exec      a static binary exec'd on the device           (64560)
COMMON_PLACEHOLDERS = {"DEV_TMP", "DEV_LOG", "KASLR_ENV", "CLIENT_UID", "APP_UID"}
INVOKE_FORMS = {
    "helper-preload": COMMON_PLACEHOLDERS | {"DEV_HELPER", "DEV_PAYLOAD"},
    "device-exec": COMMON_PLACEHOLDERS | {"DEV_ENTRY"},
}
PLACEHOLDER_RE = re.compile(r"@([A-Z_]+)@")

# The classify_shot() outcomes (runner/lib/exploit.sh) an exit_map may name.
# HELD is deliberately absent: a stage announces it with a marker, never with an
# exit status -- a held hook means the process is still running.
OUTCOMES = {"PASS", "MISS", "PANIC", "REFUSED", "DIRTY", "PARKED",
            "PRECONDITION_FAIL"}
BUILD_KEYS = {"form", "entry", "sources", "includes", "depends", "defines",
              "cflags", "opt", "ldflags", "output", "uses_target_header"}
RECIPE_KEYS = {"schema", "name", "description", "default", "stages", "entry",
               "goals"}


def _prop_list(stage, key, sep):
    """Render a [properties] list for the contract printout.

    Distinguishes "not declared" from "declared empty": exploit.sh substitutes a
    GhostLock-shaped default for an empty string, which would misreport a stage
    that genuinely owes no repairs.
    """
    props = stage.get("properties", {})
    if key not in props:
        return "(undeclared)"
    return sep.join(props[key]) or "(none)"


def die(gate, msg, hint=None):
    sys.stderr.write("\n%s: %s\n" % (gate, msg))
    if hint:
        sys.stderr.write("  %s\n" % hint)
    sys.stderr.write("\n")
    sys.exit(2)


def load_toml(path, gate, what):
    if not os.path.exists(path):
        die(gate, "%s not found: %s" % (what, os.path.relpath(path, ROOT)))
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        die("ARCH-G0-SCHEMA", "%s is not valid TOML: %s" % (os.path.relpath(path, ROOT), e))


def macros_of(header):
    """The set of macro names #defined by a header (top level, no expansion)."""
    out = set()
    try:
        with open(header, "r", errors="replace") as f:
            for line in f:
                m = DEFINE_RE.match(line)
                if m:
                    out.add(m.group(1))
    except OSError as e:
        die("ARCH-G3-FACTS", "cannot read target header %s: %s"
            % (os.path.relpath(header, ROOT), e))
    return out


def device_kmi(target):
    """The target's kernel flavour, from data/targets.json (the host runner's
    own source of truth -- runner/lib/select.sh reads the same file)."""
    if not os.path.exists(TARGETS_JSON):
        die("ARCH-G0-SCHEMA", "data/targets.json not found")
    with open(TARGETS_JSON) as f:
        data = json.load(f)
    for d in data.get("devices", []):
        if "%s-%s" % (d["codename"], d["build"]) == target:
            return d.get("kmi")
    return None


def all_kmis():
    """Every kernel flavour named by data/targets.json."""
    with open(TARGETS_JSON) as f:
        data = json.load(f)
    return {d["kmi"] for d in data.get("devices", []) if d.get("kmi")}


def rel(path):
    """Repo-relative manifest path -> path relative to cves/, which is make's
    cwd."""
    return os.path.relpath(os.path.join(ROOT, path), EXPLOIT)


def shq(v):
    """POSIX-shell single-quote one value for `eval`."""
    return "'" + str(v).replace("'", "'\\''") + "'"


def setup_of(sid, st):
    """Validate a stage's [[setup]] list and return it as a list of dicts."""
    raw = st.get("setup", [])
    if not isinstance(raw, list):
        die("ARCH-G0-SETUP", "stage %r [[setup]] must be a list of steps" % sid)
    steps = []
    for i, step in enumerate(raw):
        if not isinstance(step, dict):
            die("ARCH-G0-SETUP", "stage %r setup step %d is not a table" % (sid, i))
        stray = sorted(set(step) - SETUP_KEYS)
        if stray:
            die("ARCH-G0-SETUP", "stage %r setup step %d has unknown key(s): %s"
                % (sid, i, ", ".join(stray)),
                "known setup keys: " + ", ".join(sorted(SETUP_KEYS)))
        is_reboot = bool(step.get("reboot", False))
        cmd = step.get("command", "")
        if is_reboot and cmd:
            die("ARCH-G0-SETUP",
                "stage %r setup step %d is both a reboot and a command" % (sid, i),
                "a step reboots OR runs a command, not both")
        if not is_reboot and not (isinstance(cmd, str) and cmd.strip()):
            die("ARCH-G0-SETUP",
                "stage %r setup step %d has neither reboot nor command" % (sid, i))
        # A setup command runs on the device shell; it may use the same device
        # path placeholders an invoke command may, no more.
        if cmd:
            bad = sorted(set(PLACEHOLDER_RE.findall(cmd)) - COMMON_PLACEHOLDERS
                         - {"DEV_ENTRY"})
            if bad:
                die("ARCH-G0-SETUP",
                    "stage %r setup step %d uses unsubstitutable placeholder(s): %s"
                    % (sid, i, ", ".join("@%s@" % b for b in bad)))
        steps.append({
            "reboot": is_reboot,
            "command": cmd,
            "needs_root": bool(step.get("needs_root", False)),
            "once_per_boot": bool(step.get("once_per_boot", False)),
            "description": step.get("description", ""),
        })
    return steps


def contract_of(sid, st, target, stages, entry_build):
    """Validate and flatten the foreign-chain contract of an ENTRY stage:
    {invoke, markers, exit_map, provides}.

    Every check here fails the RUN with a named gate, for the same reason the
    build gates exist: a malformed command template must never reach a phone.
    """
    inv = st.get("invoke")
    if not isinstance(inv, dict):
        die("ARCH-G0-INVOKE",
            "stage %r declares no [invoke] table, so the runner cannot drive it" % sid,
            "add an [invoke] block naming kind and command; see "
            "runner/stages/entry.cve64560@6.1/stage.toml")

    stray = sorted(set(inv) - INVOKE_KEYS)
    if stray:
        die("ARCH-G0-SCHEMA", "stage %r [invoke] has unrecognised key(s): %s"
            % (sid, ", ".join(stray)),
            "known [invoke] keys: " + ", ".join(sorted(INVOKE_KEYS)))

    kind = inv.get("kind")
    if kind not in INVOKE_FORMS:
        die("ARCH-G0-INVOKE", "stage %r declares unknown invoke kind %r" % (sid, kind),
            "known invocation shapes: " + ", ".join(sorted(INVOKE_FORMS)))

    cmd = inv.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        die("ARCH-G0-INVOKE", "stage %r [invoke] has no command template" % sid)

    used = set(PLACEHOLDER_RE.findall(cmd))
    allowed = INVOKE_FORMS[kind]
    bad = sorted(used - allowed)
    if bad:
        die("ARCH-G0-INVOKE",
            "stage %r invoke command uses placeholder(s) the %r shape cannot "
            "substitute: %s" % (sid, kind, ", ".join("@%s@" % b for b in bad)),
            "%r may use: %s" % (kind, ", ".join("@%s@" % p for p in sorted(allowed))))

    accepts_base = bool(inv.get("accepts_base", False))
    needs_root = bool(inv.get("needs_root", False))
    if accepts_base and "KASLR_ENV" not in used:
        die("ARCH-G0-INVOKE",
            "stage %r sets accepts_base = true but its command never uses "
            "@KASLR_ENV@" % sid,
            "a cached base is replayed through that placeholder")
    if not accepts_base and "KASLR_ENV" in used:
        die("ARCH-G0-INVOKE",
            "stage %r uses @KASLR_ENV@ but sets accepts_base = false" % sid,
            "either the entry can be replayed with a base or it cannot; say which")

    # --- artifact: where the runner gets the file it pushes ------------------
    src = inv.get("artifact_source", "build")
    if src not in ("build", "runner"):
        die("ARCH-G0-INVOKE", "stage %r [invoke].artifact_source is %r" % (sid, src),
            'known sources: "build" (cves/build/<target>/<output>) or '
            '"runner" (runner/lib/select.sh picks a prebuilt from artifacts/)')
    artifact = ""
    if src == "build":
        if inv.get("artifact"):
            artifact = inv["artifact"].replace("{target}", target)
        else:
            form = entry_build.get("form")
            artifact = "cves/build/%s/%s%s" % (
                target, entry_build["output"], FORM_EXT.get(form, ""))
    dest = inv.get("dest", "")
    if kind == "device-exec" and not dest:
        die("ARCH-G0-INVOKE",
            "stage %r is device-exec but names no [invoke].dest to push to" % sid)

    # --- markers -------------------------------------------------------------
    mk = st.get("markers")
    if not isinstance(mk, dict):
        die("ARCH-G0-INVOKE",
            "stage %r declares no [markers] table" % sid,
            "the host builds its classifier from this data, not from "
            "runner/lib/exploit.sh")
    stray = sorted(set(mk) - MARKER_KEYS)
    if stray:
        die("ARCH-G0-SCHEMA", "stage %r [markers] has unrecognised key(s): %s"
            % (sid, ", ".join(stray)),
            "known [markers] keys: " + ", ".join(sorted(MARKER_KEYS)))
    if not mk.get("pass"):
        die("ARCH-G0-INVOKE", "stage %r [markers] has no `pass` pattern" % sid,
            "classify_shot needs one ERE that means 'this shot reached the "
            "stage's goal'")

    # --- exit map ------------------------------------------------------------
    emap = st.get("exit_map", {})
    if not isinstance(emap, dict):
        die("ARCH-G0-SCHEMA", "stage %r [exit_map] must be a table" % sid)
    pairs = []
    for k, v in emap.items():
        if not str(k).isdigit():
            die("ARCH-G0-SCHEMA",
                "stage %r [exit_map] key %r is not an exit status" % (sid, k))
        if v not in OUTCOMES:
            die("ARCH-G0-SCHEMA",
                "stage %r [exit_map].%s = %r is not an outcome" % (sid, k, v),
                "outcome vocabulary: " + ", ".join(sorted(OUTCOMES)))
        pairs.append("%d=%s" % (int(k), v))

    # --- provides ------------------------------------------------------------
    pv = st.get("provides", {})
    if not isinstance(pv, dict):
        die("ARCH-G0-SCHEMA", "stage %r [provides] must be a table" % sid)
    stray = sorted(set(pv) - PROVIDES_KEYS)
    if stray:
        die("ARCH-G0-SCHEMA", "stage %r [provides] has unrecognised key(s): %s"
            % (sid, ", ".join(stray)),
            "known [provides] keys: " + ", ".join(sorted(PROVIDES_KEYS)))
    if pv.get("field") and not pv.get("label"):
        die("ARCH-G0-SCHEMA",
            "stage %r [provides] names a field but no label to report it under" % sid)

    # Capability union across every SELECTED stage.  The runner uses it to decide
    # whether this chain can produce root at all: a chain with no CAP_SU handoff
    # must not ask the su oracle, or a leftover $DEV_SU from an earlier GhostLock
    # run answers for it.
    caps = []
    for other in stages.values():
        for c in other.get("properties", {}).get("provides", []):
            if c not in caps:
                caps.append(c)

    return {
        "kind": kind, "command": cmd, "accepts_base": accepts_base,
        "needs_root": needs_root,
        "artifact_source": src, "artifact": artifact, "dest": dest,
        "mode": str(inv.get("mode", "755")),
        "markers": mk, "exit_map": " ".join(pairs),
        "provides_caps": " ".join(pv.get("caps", [])),
        "provides_field": pv.get("field", ""),
        "provides_label": pv.get("label", ""),
        "chain_caps": " ".join(caps),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--recipe", default="ghostlock")
    ap.add_argument("--format", default="make", choices=("make", "json", "shell"))
    ap.add_argument("--build-tag", default="",
                    help="pin BUILD_TAG instead of __DATE__ __TIME__, making "
                         "the 6.1 payloads byte-reproducible")
    args = ap.parse_args()

    target = args.target
    recipe_name = args.recipe

    # --- ARCH-G0-TARGET ---------------------------------------------------
    tdir = os.path.join(EXPLOIT, "targets", target)
    if not os.path.isdir(tdir):
        known = sorted(os.listdir(os.path.join(EXPLOIT, "targets")))
        die("ARCH-G0-TARGET", "unknown target %r" % target,
            "known targets: " + ", ".join(known))

    # --- ARCH-G0-RECIPE ---------------------------------------------------
    rpath = os.path.join(RECIPES, recipe_name + ".toml")
    if not os.path.exists(rpath):
        known = sorted(f[:-5] for f in os.listdir(RECIPES) if f.endswith(".toml"))
        die("ARCH-G0-RECIPE", "unknown recipe %r" % recipe_name,
            "known recipes: " + ", ".join(known)
            + "  (recipes live in runner/recipes/*.toml)")
    recipe = load_toml(rpath, "ARCH-G0-RECIPE", "recipe")

    stray = sorted(set(recipe) - RECIPE_KEYS)
    if stray:
        die("ARCH-G0-SCHEMA",
            "recipe %r has unrecognised key(s): %s" % (recipe_name, ", ".join(stray)),
            "known recipe keys: " + ", ".join(sorted(RECIPE_KEYS)))

    entry_map = recipe.get("entry")
    if not isinstance(entry_map, dict) or not entry_map:
        die("ARCH-G0-SCHEMA", "recipe %r has no [entry] table" % recipe_name,
            "a recipe must pin an entry stage per kernel flavour, e.g.\n"
            '    [entry]\n    "android14-6.1" = "entry.ghostlock@6.1"')

    # Every key in [entry] must be a kernel flavour that some device actually
    # has.  A bare key written *after* the [entry] header (e.g.
    # `stages = [...]`) would otherwise become a member of it.
    known_kmis = all_kmis()
    for k, v in entry_map.items():
        if k not in known_kmis:
            die("ARCH-G0-SCHEMA",
                "recipe %r [entry] has key %r, which is not a kernel flavour"
                % (recipe_name, k),
                "flavours in data/targets.json: " + ", ".join(sorted(known_kmis))
                + "\n  (a bare key written after the [entry] header becomes part "
                  "of it -- move it above)")
        if not isinstance(v, str):
            die("ARCH-G0-SCHEMA",
                "recipe %r [entry].%s must be a stage id string, got %r"
                % (recipe_name, k, v))

    # --- the target's kernel flavour, from two independent sources ---------
    kmi = device_kmi(target)
    if kmi is None:
        die("ARCH-G0-TARGET", "target %r has a header but no data/targets.json row"
            % target,
            "add a devices[] entry with its codename, build and kmi")

    header = os.path.join(tdir, "target.h")
    hdr_macros = macros_of(header)

    # --- ARCH-G9-XSRC: targets.json vs the header itself --------------------
    for marker_kmi, markers in KMI_MARKERS.items():
        present = [m for m in markers if m in hdr_macros]
        looks_like = len(present) == len(markers)
        if looks_like and kmi != marker_kmi:
            die("ARCH-G9-XSRC",
                "target %r is %r in data/targets.json but its target.h defines "
                "all %d %s markers (%s)" % (target, kmi, len(markers),
                                            marker_kmi, ", ".join(markers)),
                "one of the two sources is wrong; fix it before building")
        if not present and kmi == marker_kmi:
            die("ARCH-G9-XSRC",
                "target %r is %r in data/targets.json but its target.h defines "
                "none of the %s markers (%s)" % (target, kmi, marker_kmi,
                                                 ", ".join(markers)),
                "one of the two sources is wrong; fix it before building")

    # --- ARCH-G1-KMI: does this recipe cover the target's flavour? ----------
    if kmi not in entry_map:
        die("ARCH-G1-KMI",
            "recipe %r has no entry for kernel flavour %r (target %s)"
            % (recipe_name, kmi, target),
            "recipe %r covers: %s" % (recipe_name, ", ".join(sorted(entry_map))))
    entry_id = entry_map[kmi]

    selected = [entry_id] + list(recipe.get("stages", []))

    stages = {}
    for sid in selected:
        spath = os.path.join(STAGES, sid, "stage.toml")
        if not os.path.exists(spath):
            known = sorted(d for d in os.listdir(STAGES)
                           if os.path.exists(os.path.join(STAGES, d, "stage.toml")))
            die("ARCH-G0-STAGE",
                "recipe %r names stage %r, but runner/stages/%s/stage.toml does not exist"
                % (recipe_name, sid, sid),
                "known stages: " + ", ".join(known))
        stages[sid] = load_toml(spath, "ARCH-G0-STAGE", "stage manifest")

    # --- per-stage gates ---------------------------------------------------
    for sid, st in stages.items():
        stray = sorted(set(st) - STAGE_KEYS)
        if stray:
            die("ARCH-G0-SCHEMA",
                "stage %r has unrecognised key(s): %s" % (sid, ", ".join(stray)),
                "known stage keys: " + ", ".join(sorted(STAGE_KEYS)))

        build = st.get("build")
        if not isinstance(build, dict):
            die("ARCH-G0-SCHEMA", "stage %r has no [build] table" % sid)

        # Any dict-valued key under [build] is a build variant ([build.release]);
        # anything else must be a recognised build key.
        stray = sorted(k for k, v in build.items()
                       if k not in BUILD_KEYS and not isinstance(v, dict))
        if stray:
            die("ARCH-G0-SCHEMA",
                "stage %r [build] has unrecognised key(s): %s" % (sid, ", ".join(stray)),
                "known [build] keys: " + ", ".join(sorted(BUILD_KEYS))
                + "\n  (a bare key written after a [table] header becomes part of "
                  "that table -- move it above)")

        # ARCH-G1-KMI, second half: the stage must itself claim this flavour.
        skmi = st.get("kmi", [])
        if skmi and kmi not in skmi:
            die("ARCH-G1-KMI",
                "stage %r declares kmi %s but target %s is %r"
                % (sid, skmi, target, kmi),
                "recipe %r pinned this stage for the wrong kernel flavour"
                % recipe_name)

        # ARCH-G0-TARGETSET: stage restricted to specific targets.
        tset = st.get("targets")
        if tset and target not in tset:
            die("ARCH-G0-TARGETSET",
                "stage %r supports only %s, not %s" % (sid, ", ".join(tset), target),
                "stage %r has no offsets for this target; %s"
                % (sid, st.get("facts", {}).get("generator")
                   and "generate them with " + st["facts"]["generator"]
                   or "no generator is declared"))

        # ARCH-G3-FACTS: required / forbidden target facts.
        facts = st.get("facts", {})
        fhdr_tpl = facts.get("header")
        if fhdr_tpl:
            fhdr = os.path.join(ROOT, fhdr_tpl.replace("{target}", target))
            if not os.path.exists(fhdr):
                die("ARCH-G3-FACTS",
                    "stage %r needs fact header %s, which does not exist"
                    % (sid, os.path.relpath(fhdr, ROOT)),
                    facts.get("generator")
                    and "generate it with " + facts["generator"] or None)
            fmacros = macros_of(fhdr)
        else:
            fmacros = hdr_macros

        missing = [m for m in facts.get("requires", []) if m not in fmacros]
        if missing:
            die("ARCH-G3-FACTS",
                "stage %r requires %d target fact(s) absent from %s: %s"
                % (sid, len(missing), os.path.relpath(
                    os.path.join(ROOT, (fhdr_tpl or "").replace("{target}", target))
                    if fhdr_tpl else header, ROOT), ", ".join(missing)),
                "the target header does not describe the kernel this stage "
                "exploits; do not build this pairing")

        present_forbidden = [m for m in facts.get("forbids", []) if m in fmacros]
        if present_forbidden:
            die("ARCH-G3-FACTS",
                "stage %r forbids %d fact(s) that %s defines: %s"
                % (sid, len(present_forbidden), os.path.relpath(header, ROOT),
                   ", ".join(present_forbidden)),
                "this stage's sources define those macros unguarded, so the "
                "stage's value would silently win over the target's")

    # --- build the artifact table -----------------------------------------
    goals = recipe.get("goals", {})
    wanted = []
    for goal in ("all", "release"):
        for ref in goals.get(goal, []):
            if ref not in wanted:
                wanted.append(ref)

    artifacts = {}   # make-safe key -> dict
    goal_keys = {"all": [], "release": []}
    owners = {}      # output filename -> stage id, for ARCH-G8

    def make_key(ref):
        return re.sub(r"[^A-Za-z0-9]", "_", ref)

    for ref in wanted:
        # NB: stage ids contain "@" (entry.ghostlock@6.1), so the variant
        # separator must be something else.  "entry:release".
        sid, _, variant = ref.partition(":")
        if sid == "entry":
            sid = entry_id
        if sid not in stages:
            die("ARCH-G0-STAGE",
                "recipe %r [goals] names %r, which is not a selected stage"
                % (recipe_name, ref),
                "selected stages: " + ", ".join(selected))
        st = stages[sid]
        build = dict(st["build"])
        if variant:
            sub = build.get(variant)
            if not isinstance(sub, dict):
                die("ARCH-G0-SCHEMA",
                    "stage %r has no [build.%s] variant (wanted by recipe %r)"
                    % (sid, variant, recipe_name))
            build.update(sub)

        form = build.get("form")
        if form not in FORM_EXT:
            die("ARCH-G0-SCHEMA",
                "stage %r declares unknown build form %r" % (sid, form),
                "known forms: " + ", ".join(sorted(FORM_EXT)))

        out = build["output"] + FORM_EXT[form]
        if out in owners and owners[out] != ref:
            die("ARCH-G8-WRITER",
                "artifact %s is claimed by both %s and %s" % (out, owners[out], ref),
                "each artifact must have exactly one producing stage")
        owners[out] = ref

        # ---- the compile line ------------------------------------------
        # Order is fixed:
        #   -D<defines>  <cflags with @OPT@ expanded>  <-I...>
        #   <target defines>  [-DBUILD_TAG]   <srcs>   <ldflags>  -o <out>
        cflags = []
        for d in build.get("defines", []):
            cflags.append("-D" + d)
        opt = build.get("opt", [])
        for f in build.get("cflags", []):
            if f == "@OPT@":
                cflags.extend(opt)
            else:
                cflags.append(f)
        for inc in build.get("includes", []):
            cflags.append("-I" + rel(inc))
        if build.get("uses_target_header", True):
            ti = "targets/%s/target.h" % target
            cflags.append("-DTARGET_HEADER='\"%s\"'" % ti)
            cflags.append("-DTARGET_CONFIG_H='\"%s\"'" % ti)
        if args.build_tag:
            cflags.append("-DBUILD_TAG='\"%s\"'" % args.build_tag)

        srcs = [rel(s) for s in build.get("sources", [])]
        deps = [rel(d) for d in build.get("depends", [])]
        if build.get("uses_target_header", True):
            deps = deps + [rel("cves/cve-2026-43499-ghostlock/offset.h")]
        fh = st.get("facts", {}).get("header")
        if fh:
            deps = deps + [rel(fh.replace("{target}", target))]

        key = make_key(ref)
        artifacts[key] = {
            "ref": ref, "stage": sid, "variant": variant or "default",
            "form": form, "out": out, "srcs": srcs, "deps": deps,
            "cflags": cflags, "ldflags": build.get("ldflags", []),
        }

    for goal in ("all", "release"):
        goal_keys[goal] = [make_key(r) for r in goals.get(goal, [])]

    # --- emit --------------------------------------------------------------
    if args.format == "shell":
        # The RUN-time half of this resolver: the foreign-chain
        # contract, shell-quoted for `eval` by runner/lib/exploit.sh's
        # load_entry_contract().  The same recipe name, manifests and gates as
        # the build.
        c = contract_of(entry_id, stages[entry_id], target, stages,
                        stages[entry_id]["build"])
        mk = c["markers"]
        out = [
            ("RUN_RECIPE", recipe_name),
            ("RUN_TARGET", target),
            ("RUN_KMI", kmi),
            ("RUN_ENTRY", entry_id),
            ("RUN_ENTRY_CVE", stages[entry_id].get("cve", "")),
            ("RUN_ENTRY_COMPOSED",
             "yes" if stages[entry_id].get("composed", False) else "no"),
            ("RUN_ENTRY_STATUS", stages[entry_id].get("status", "")),
            ("RUN_STAGES", " ".join(selected)),
            ("RUN_INVOKE_KIND", c["kind"]),
            ("RUN_INVOKE_CMD", c["command"]),
            ("RUN_INVOKE_ACCEPTS_BASE", "1" if c["accepts_base"] else "0"),
            ("RUN_INVOKE_NEEDS_ROOT", "1" if c["needs_root"] else "0"),
            ("RUN_INVOKE_SOURCE", c["artifact_source"]),
            ("RUN_INVOKE_ARTIFACT", c["artifact"]),
            ("RUN_INVOKE_DEST", c["dest"]),
            ("RUN_INVOKE_MODE", c["mode"]),
            ("RUN_MARK_PASS", mk.get("pass", "")),
            ("RUN_MARK_GATE_FAIL", mk.get("gate_fail", "")),
            ("RUN_MARK_RESTORE_PASS", mk.get("restore_pass", "")),
            ("RUN_MARK_RESTORE_BAD", mk.get("restore_bad", "")),
            ("RUN_MARK_HEARTBEAT", mk.get("heartbeat", "")),
            ("RUN_MARK_DIAG", mk.get("diag", "")),
            ("RUN_MARK_DIAG_COUNT", mk.get("diag_count", "")),
            ("RUN_EXIT_MAP", c["exit_map"]),
            ("RUN_PROVIDES_CAPS", c["provides_caps"]),
            ("RUN_PROVIDES_FIELD", c["provides_field"]),
            ("RUN_PROVIDES_LABEL", c["provides_label"]),
            ("RUN_CHAIN_CAPS", c["chain_caps"]),
            ("RUN_PROP_RETRY_SAFE",
             "yes" if stages[entry_id].get("properties", {}).get("retry_safe")
             else "no"),
            ("RUN_PROP_PANIC_PRE",
             stages[entry_id].get("properties", {})
             .get("panic_risk", {}).get("pre_slide", "unknown")),
            ("RUN_PROP_PANIC_POST",
             stages[entry_id].get("properties", {})
             .get("panic_risk", {}).get("post_slide", "unknown")),
            # A stage that declares NOTHING destructive must not be reported
            # with the built-in GhostLock defaults exploit.sh falls back to on
            # an empty value, so say which of the two silences this is: the key
            # absent (nobody has decided) or the key present and empty (decided,
            # and the answer is none). Both are non-empty strings, so the shell's
            # `:-` default only fires on the no-manifest path, where the built-in
            # GhostLock text is the right answer.
            ("RUN_PROP_RESTORES", _prop_list(stages[entry_id], "restores", " ")),
            ("RUN_PROP_DESTRUCTIVE", _prop_list(stages[entry_id], "destructive", "; ")),
        ]
        # Setup steps: an ordered list the runner runs before each shot. Emitted
        # as a count plus five vars per step, so load_entry_contract() can read
        # them into parallel arrays without parsing structure out of one string.
        setup = setup_of(entry_id, stages[entry_id])
        out.append(("RUN_SETUP_COUNT", str(len(setup))))
        for i, step in enumerate(setup):
            out.append(("RUN_SETUP_%d_REBOOT" % i, "1" if step["reboot"] else "0"))
            out.append(("RUN_SETUP_%d_CMD" % i, step["command"]))
            out.append(("RUN_SETUP_%d_ROOT" % i, "1" if step["needs_root"] else "0"))
            out.append(("RUN_SETUP_%d_ONCE" % i, "1" if step["once_per_boot"] else "0"))
            out.append(("RUN_SETUP_%d_DESC" % i, step["description"]))
        print("# GENERATED by runner/scripts/resolve-recipe.py --format shell -- do not edit.")
        print("# recipe=%s target=%s kmi=%s entry=%s" % (recipe_name, target, kmi, entry_id))
        for k, v in out:
            print("%s=%s" % (k, shq(v)))
        return

    if args.format == "json":
        print(json.dumps({
            "recipe": recipe_name, "target": target, "kmi": kmi,
            "entry": entry_id, "stages": selected,
            "composed": all(stages[s].get("composed", False) for s in stages),
            "artifacts": artifacts, "goals": goal_keys,
        }, indent=2))
        return

    w = sys.stdout.write
    w("# GENERATED by runner/scripts/resolve-recipe.py -- do not edit.\n")
    w("# recipe=%s target=%s kmi=%s entry=%s\n" % (recipe_name, target, kmi, entry_id))
    w("RECIPE_NAME := %s\n" % recipe_name)
    w("RECIPE_KMI := %s\n" % kmi)
    w("RECIPE_ENTRY := %s\n" % entry_id)
    w("RECIPE_STAGES := %s\n" % " ".join(selected))
    w("RECIPE_COMPOSED := %s\n" % ("yes" if all(
        stages[s].get("composed", False) for s in stages) else "no"))
    w("ARTIFACTS := %s\n" % " ".join(artifacts))
    for key, a in artifacts.items():
        w("ART_%s_REF := %s\n" % (key, a["ref"]))
        w("ART_%s_STAGE := %s\n" % (key, a["stage"]))
        w("ART_%s_OUT := %s\n" % (key, a["out"]))
        w("ART_%s_SRCS := %s\n" % (key, " ".join(a["srcs"])))
        w("ART_%s_DEPS := %s\n" % (key, " ".join(a["deps"])))
        w("ART_%s_CFLAGS := %s\n" % (key, " ".join(a["cflags"])))
        w("ART_%s_LDFLAGS := %s\n" % (key, " ".join(a["ldflags"])))
    w("GOAL_ALL := %s\n" % " ".join(goal_keys["all"]))
    w("GOAL_RELEASE := %s\n" % " ".join(goal_keys["release"]))


if __name__ == "__main__":
    main()
