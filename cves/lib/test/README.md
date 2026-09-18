# cves/lib/test — checking what can be checked away from a device

Most of this library only means anything against a running kernel. A specific part of it
does not: address conversions, hash models, field tables and buffer composition are pure
arithmetic over values the target description supplies. That part is both testable anywhere
and the part where a silent mistake costs most, because a conversion wrong by a page yields
a perfectly plausible address, and the first sign of the error is a device that has already
been written to.

So the rule is that whatever can be checked without a kernel is checked, and whatever
cannot is left to the build gates and to hardware. Nothing is approximated with a mock,
because a mock of a kernel tests the mock.

## Two checks, answering different questions

*Is the description self-consistent, and does the arithmetic hold?* That is `selftest.c`.
Conversions must invert each other across the whole linear map, buffer accessors must be
exact at every alignment, a hash index must land inside its table, structure fields must
lie inside their structures, and the run outcomes must stay distinct. It can be run against
any build's description, because the rules hold for all of them.

```sh
cc -o selftest lib/test/selftest.c && ./selftest
cc -DTARGET_HEADER='"../targets/<build>/target.h"' -o selftest lib/test/selftest.c
```

*Does the description match the kernel?* That is `runner/scripts/verify-target.py`.
Self-consistency cannot catch a transcription error: a field offset that names the wrong
field, or a flag position that names a different flag, is perfectly consistent and simply
wrong. Catching that needs an external source of truth, and the kernel carries one — its
own embedded [type information](https://docs.kernel.org/bpf/btf.html), the same data a
running kernel serves.

```sh
runner/scripts/verify-target.py <build>
```

Both are worth running, because neither subsumes the other. The first needs no capture and
covers every build; the second needs type information for the exact build, and covers only
the facts declared checkable in `runner/scripts/lib/offset-maps.txt`.

## On tests that cannot fail

A check that passes no matter what is worse than no check, because it reads as coverage.
Every check here was confirmed against a deliberately broken input before being kept, and
each one has caught a real defect — a misnamed flag position, a structure offset off by a
field — under exactly that treatment.

One check had to be strengthened for the same reason. Reading a capability mask with an
inferred numeric base yields a small integer rather than the mask, and an assertion that
the value is merely non-zero passes regardless. The assertion is on the magnitude instead.
