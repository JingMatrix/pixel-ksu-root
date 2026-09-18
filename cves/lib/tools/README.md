# cves/lib/tools — the library's instruments

Shell counterparts to the C modules beside them: shared techniques an exploit
invokes rather than links. They are part of the library for the same reason the
headers are — each answers a question several investigations ask, and answering
it once is what keeps the answers consistent.

| tool | question it answers | runs on |
|---|---|---|
| `kprobe.sh` | was this function reached, with what arguments; what is at this address | the device, as root |
| `symbol-shape.sh` | is a fix present, judged by which symbols exist | the device |
| `module-shape.sh` | is a fix present, judged by the compiled shape of one function | a workstation |
| `binary-strings.sh` | is a fix present, judged by a string the fix introduced | a workstation |

The three presence tests share one contract, so a caller reads them the same
way: a printed verdict, and an exit status of 0 for fixed, 1 for unfixed, 2 for
inconclusive, and 3 for a build the defect does not apply to. Inconclusive is a
real outcome and is never collapsed into one of the others — a symbol can be
absent because it was inlined, and a pattern can be missing because the compiler
chose differently, neither of which is evidence about the fix.

A per-defect `probe.sh` is a few lines naming that defect's discriminator and
delegating here. The discriminator is the interesting part and belongs with the
defect; the mechanics of pulling a module, locating a symbol or restoring the
trace buffer do not.

Tooling that builds or checks the repository — rather than something an exploit
invokes — lives in [`runner/scripts/`](../../../runner/scripts/).

## On leaving no trace

`kprobe.sh` removes every probe and restores the tracing state on the way out,
including on its `peek` path. This is not tidiness: a probe left enabled changes
the timing of every later step on that boot, and timing is what most of the work
in this tree measures. A run that observes itself into a different outcome has
measured nothing.
