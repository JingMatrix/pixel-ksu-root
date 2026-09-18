#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Correlate a pagetrace ring-buffer dump by phase and by PFN.

The probe writes its phase names into trace_marker, so every page event can be
attributed to the phase it happened in; pages are then followed by PFN across
allocation, discard and reclaim.  An order-N block at PFN P covers P..P+2^N-1,
so a reclaim hit is any allocation whose block covers a discarded page.
"""
import re
import sys
from collections import defaultdict

# TASK-PID [CPU] FLAGS TIMESTAMP: event: ... — the flags column ('.....') sits
# between the cpu and the timestamp and must be consumed explicitly.
EV = re.compile(r'^\s*(\S+?)-(\d+)\s+\[(\d+)\]\s+\S+\s+(\d+\.\d+): '
                r'mm_page_(alloc_zone_locked|pcpu_drain|alloc|free): '
                r'page=\S+ pfn=(0x[0-9a-f]+) order=(\d+)'
                r'(?: migratetype=(-?\d+))?')
MARK = re.compile(r'\s(\d+\.\d+): tracing_mark_write: (.*)$')
MIGRATE = {0: 'unmovable', 1: 'movable', 2: 'reclaimable', 3: 'pcptypes', 4: 'cma'}


def parse(path):
    events, marks, phase = [], {}, '(pre)'
    for line in open(path):
        m = MARK.search(line)
        if m:
            phase = m.group(2).strip()
            marks.setdefault(phase, float(m.group(1)))
            continue
        m = EV.match(line)
        if m:
            events.append(dict(comm=m.group(1), cpu=int(m.group(3)),
                               ts=float(m.group(4)), kind=m.group(5),
                               pfn=int(m.group(6), 16), order=int(m.group(7)),
                               mt=int(m.group(8)) if m.group(8) else None,
                               phase=phase))
    return events, marks


def covers(pfn, order):
    return range(pfn, pfn + (1 << order))


def main(path):
    ev, marks = parse(path)
    if not ev:
        print('no page events — were the tracepoints armed?')
        return

    by_phase = defaultdict(lambda: [0, 0])
    for e in ev:
        by_phase[e['phase']][0 if e['kind'] == 'alloc' else 1] += 1
    print('phase                     allocs   frees')
    for ph in dict.fromkeys(e['phase'] for e in ev):
        a, f = by_phase[ph]
        print(f'  {ph:<22} {a:7d} {f:7d}')

    # allocation-class identification: what did one class actually take?
    cls = [e for e in ev if e['phase'] == 'CLASS_START' and e['kind'] == 'alloc']
    if cls:
        seen = defaultdict(int)
        for e in cls:
            seen[(e['order'], e['mt'])] += 1
        print('\nallocation class:')
        for (order, mt), n in sorted(seen.items(), key=lambda x: -x[1]):
            name = MIGRATE.get(mt, mt)
            print(f'  order={order} migratetype={mt} ({name})  x{n}')

    # slab lifecycle: pages we placed objects on, and what became of them
    placed = {e['pfn'] for e in ev
              if e['kind'] == 'alloc' and e['order'] == 1 and e['phase'] == 'SLAB_FILL_START'}
    if not placed:
        return
    freed = {}
    for e in ev:
        if e['kind'] == 'free' and e['pfn'] in placed and e['pfn'] not in freed:
            freed[e['pfn']] = e
    close = marks.get('VICTIM_CLOSE_END')
    print(f'\nslab pages we placed objects on : {len(placed)}')
    pct = 100 * len(freed) // len(placed)
    print(f'  discarded to the buddy allocator: {len(freed)}  ({pct}%)')
    if freed and close:
        lat = sorted(e['ts'] - close for e in freed.values())
        who = sorted({(e['comm'], e['cpu']) for e in freed.values()})
        print(f'  discard window                  : +{lat[0]:.3f}s .. +{lat[-1]:.3f}s after close')
        print(f'  discarded by                    : {", ".join(f"{c} on cpu{n}" for c, n in who)}')

    if any(e['kind'] in ('pcpu_drain', 'alloc_zone_locked') for e in ev):
        fate(ev, marks, placed, freed)

    spray = [e for e in ev if e['kind'] == 'alloc' and e['phase'].startswith('SPRAY')]
    if not spray:
        return
    taken = set()
    for e in spray:
        taken.update(covers(e['pfn'], e['order']))
    hits = {p for p in freed if any(q in taken for q in covers(p, 1))}
    # only count reclaims that happened after the page was discarded
    hits = {p for p in hits
            if any(e['ts'] > freed[p]['ts'] and p in covers(e['pfn'], e['order'])
                   for e in spray)}
    print(f'  pages taken by the reclaim spray: {len(spray)}')
    print(f'  >>> SPRAY TOOK A DISCARDED SLAB PAGE: {len(hits)}'
          f'{"  " + ", ".join(hex(p) for p in sorted(hits)[:5]) if hits else ""}')


def fate(ev, marks, placed, freed):
    """Follow each discarded page and say what became of it.

    The two hypotheses this separates: the page is parked on the per-cpu list of
    whichever CPU released it (then a pcpu_drain must precede any reuse), or it
    went to the buddy freelists (then a reuse shows as alloc_zone_locked, and a
    reuse at a lower pfn with a bigger order means it coalesced first).
    """
    later = [e for e in ev if e['kind'] in ('pcpu_drain', 'alloc', 'alloc_zone_locked')]
    print('\nfate of each discarded slab page')
    drained = reused = untouched = 0
    for pfn, fe in sorted(freed.items(), key=lambda x: x[1]['ts']):
        hits = [e for e in later
                if e['ts'] > fe['ts'] and e['pfn'] <= pfn < e['pfn'] + (1 << e['order'])]
        if not hits:
            untouched += 1
            continue
        for e in hits[:3]:
            tag = {'pcpu_drain': 'drained pcp -> buddy',
                   'alloc_zone_locked': 'allocated FROM BUDDY',
                   'alloc': 'allocated'}[e['kind']]
            coalesced = '' if e['pfn'] == pfn and e['order'] == 1 else \
                        f" (inside an order-{e['order']} block at {hex(e['pfn'])}: coalesced)"
            print(f"  {hex(pfn)}  +{e['ts'] - fe['ts']:6.3f}s  {tag:22s} by {e['comm']} on cpu{e['cpu']}{coalesced}")
        if any(e['kind'] == 'pcpu_drain' for e in hits):
            drained += 1
        if any(e['kind'] != 'pcpu_drain' for e in hits):
            reused += 1
    print(f"\n  discarded pages           : {len(freed)}")
    print(f"  drained from pcp to buddy : {drained}")
    print(f"  re-allocated by anyone    : {reused}")
    print(f"  never touched again       : {untouched}")
    if untouched == len(freed) and freed:
        print("  => the page is parked and never offered back within the window")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '/dev/stdin')
