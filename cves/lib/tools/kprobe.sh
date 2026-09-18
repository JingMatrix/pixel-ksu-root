#!/system/bin/sh
# kprobe.sh -- arm, read and remove dynamic kernel probes. Runs on the device,
# as root.
#
# A probe is the tree's general-purpose observation instrument: it answers
# "was this function reached, with what arguments" without changing anything,
# and "what is at this address" for a run that is already privileged. Both come
# from the same tracing interface and the same three steps -- describe the
# probe, enable it, read the buffer -- which is why they live here once rather
# than inline in each investigation.
#
# Two properties make the difference between an instrument and an accident:
#
#   Every probe is removed and tracing is restored on the way out, because a
#   probe left enabled changes the timing of every later step on that boot, and
#   timing is what most of the work here measures.
#
#   Every probe is filtered to one process where a filter is possible. An
#   unfiltered probe on a busy function fills the buffer with unrelated hits and
#   the one that matters is lost.
#
# Commands:
#   arm <name> <spec> [filter]  install and enable one probe
#   arm-return <name> <fn>      the same, on the function's return
#   read <name> [timeout_ms]    print matching trace lines, waiting if needed
#   peek <addr> [count]         read <count> words at a literal kernel address
#   clear                       remove every probe, restore tracing
#
# <spec> is the tracing interface's own probe grammar, e.g.
#   'func arg=%x0'                     the first argument
#   'func field=+0x20(%x0):x64'        a field of the structure it points at
#   'func word=@0xffffff8000001000:x64' a literal address
#
# Usage: kprobe.sh <command> [args...]
set -u

T=/sys/kernel/tracing
[ -d "$T" ] || T=/sys/kernel/debug/tracing
[ -d "$T" ] || { echo "kprobe: no tracing interface"; exit 2; }

die() { echo "kprobe: $*" >&2; exit 2; }

# Kernel pointers are masked in trace output unless this is relaxed. Restored by
# `clear`, together with everything else this script changes.
unmask() { echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; }

clear_all() {
  for e in $(ls "$T/events/kprobes" 2>/dev/null); do
    [ -d "$T/events/kprobes/$e" ] && echo 0 > "$T/events/kprobes/$e/enable" 2>/dev/null
  done
  echo 0 > "$T/tracing_on" 2>/dev/null
  : > "$T/trace" 2>/dev/null
  echo > "$T/kprobe_events" 2>/dev/null
  echo 1 > /proc/sys/kernel/kptr_restrict 2>/dev/null
}

cmd=${1:-}; shift 2>/dev/null || true
case "$cmd" in
  arm)
    name=${1:?probe name}; spec=${2:?probe spec}; filter=${3:-}
    unmask
    echo "p:$name $spec" >> "$T/kprobe_events" || die "the kernel rejected: p:$name $spec"
    [ -n "$filter" ] && { echo "$filter" > "$T/events/kprobes/$name/filter" || die "filter rejected: $filter"; }
    echo 1 > "$T/events/kprobes/$name/enable" || die "could not enable $name"
    echo 1 > "$T/tracing_on"
    echo "ARMED $name"
    ;;
  arm-return)
    # The same, on the function's return. The distinction is the difference
    # between "this started" and "this finished", which is the only way to say
    # on which side of a free an event fell when the freeing function does
    # other work first. A return carries no arguments: the registers holding
    # them are gone by then, so the spec names the function and nothing else.
    name=${1:?probe name}; spec=${2:?probe spec}; filter=${3:-}
    unmask
    echo "r:$name $spec" >> "$T/kprobe_events" || die "the kernel rejected: r:$name $spec"
    [ -n "$filter" ] && { echo "$filter" > "$T/events/kprobes/$name/filter" || die "filter rejected: $filter"; }
    echo 1 > "$T/events/kprobes/$name/enable" || die "could not enable $name"
    echo 1 > "$T/tracing_on"
    echo "ARMED $name"
    ;;
  read)
    name=${1:?probe name}; budget=${2:-2000}
    waited=0
    while [ "$waited" -lt "$budget" ]; do
      if grep -q ": $name:" "$T/trace" 2>/dev/null; then
        grep ": $name:" "$T/trace"
        exit 0
      fi
      sleep 0.05
      waited=$((waited + 50))
    done
    echo "NOHIT $name"
    exit 1
    ;;
  peek)
    # A privileged run reading its own chosen address: probe a syscall it is
    # about to make, fetch words from a literal address, make the call. The
    # probe is filtered to this shell's own process so nothing else's traffic
    # lands in the buffer.
    addr=${1:?address}; count=${2:-1}
    spec="__arm64_sys_getpid"
    i=0
    while [ "$i" -lt "$count" ]; do
      spec="$spec w$i=@$(printf '0x%x' $((addr + i * 8))):x64"
      i=$((i + 1))
    done
    unmask
    echo > "$T/kprobe_events" 2>/dev/null
    echo "p:peek $spec" >> "$T/kprobe_events" || die "the kernel rejected the fetch at $addr"
    echo "common_pid==$$" > "$T/events/kprobes/peek/filter" 2>/dev/null
    echo 1 > "$T/events/kprobes/peek/enable"
    echo 1 > "$T/tracing_on"
    # The libc wrapper caches this value after its first real call, so the
    # syscall has to be made in a way that always enters the kernel.
    cat /proc/self/stat > /dev/null
    grep ": peek:" "$T/trace" | head -1
    clear_all
    ;;
  clear)
    clear_all
    echo "CLEARED"
    ;;
  *)
    echo "usage: $0 arm <name> <spec> [filter] | read <name> [timeout_ms] | peek <addr> [count] | clear" >&2
    exit 2
    ;;
esac
