# cves/lib/test — checking what can be checked away from a device

Most of this library only means anything against a running kernel. A specific
part of it does not: address conversions, hash models, field tables and buffer
composition are pure arithmetic over values the target description supplies.
That part is both testable anywhere and where a silent mistake costs most — a
conversion wrong by a page yields a plausible address, and the first sign of it
is a device that has already been written to.

So the rule is: whatever can be checked without a kernel is checked, and
whatever cannot is left to the build gates and to hardware. Nothing is
approximated with a mock, because a mock of a kernel tests the mock.

## Two checks, answering different questions

**`selftest.c` — is the description self-consistent, and does the arithmetic
hold?** Conversions invert each other across the whole linear map, buffer
accessors are exact at every alignment, a hash index lands inside its table,
structure fields lie inside their structures, and the four run outcomes stay
distinct. Run it against any build's description; the rules hold for all of
them.

```sh
cc -o selftest lib/test/selftest.c && ./selftest
cc -DTARGET_HEADER='"../targets/<build>/target.h"' -o selftest lib/test/selftest.c
```

`runner/scripts/verify-target.py` — does the description match the kernel?
Self-consistency cannot catch a transcription error: a field offset that names
the wrong field, or a flag position that names a different flag, is perfectly
consistent and simply wrong. That needs an external source of truth, and the
kernel carries one — its own embedded type information, the same data a running
kernel serves.

```sh
runner/scripts/verify-target.py <build>
```

Both are worth running because neither subsumes the other. The first needs no
capture and covers every build; the second needs type information for the exact
build and covers only facts declared checkable in
`runner/scripts/lib/offset-maps.txt`.

## On tests that cannot fail

A check that passes no matter what is worse than no check, because it reads as
coverage. Every check here was confirmed against a deliberately broken input
before being kept — including the three defects the consolidation exposed, all
of which the pair now catches: two flag positions, one structure offset.

One check had to be strengthened for that reason. Reading a capability mask with
an inferred numeric base yields `1` rather than the mask, and an assertion that
the value is merely non-zero passes. The assertion is on the magnitude instead.
