# Luac0re Invariant Audit for TontoJB Logs

This report is generated from captured logs only. It does not execute exploit code.

## Verdict Summary

- **BROKEN**: 1
- **FAILED_AFTER_STAGE1**: 10
- **NO_STAGE1**: 23
- **UNTRUSTED_RW_CLAIM**: 2

## Per-Tanda Audit

| Tanda | Chain | Mode(s) | Alias | PT phases | Verdict | Reason |
|---:|---|---|---|---|---|---|
| 1 | 290201 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 2 | 290201 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 3 | 290569 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 4 | 291663 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 5 | 292502 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 6 | 292628 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 7 | 292628 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 8 | 292628 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 9 | 292628 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 10 | 292628 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 11 | 292663 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 12 | 292690 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 13 | 292754 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 14 | 293357 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 15 | 14011 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 16 | 14180 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 17 | 13863 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 18 | 13708 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 19 | 13802 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 20 | 14058 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 23 | 14590 | Triple-Free Race | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 24 | 64056 | KNOTE RECLAIM (KASLR LEAK) | 31<->32, 31<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 25 | 64347 | KNOTE RECLAIM (KASLR LEAK) | 31<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 26 | 73388 | KNOTE RECLAIM (KASLR LEAK) | 31<->32, 29<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 27 | 70532 | RTHDR RECLAIM (KASLR LEAK); KQUEUE RECLAIM (KASLR LEAK) | 31<->32 | - | UNTRUSTED_RW_CLAIM | R/W was claimed before a triplet-ready invariant appeared; reclaim marker exists but does not prove independent primitive |
| 28 | 74716 | RTHDR RECLAIM (KASLR LEAK) | 31<->32 | - | BROKEN | critical runtime error present |
| 29 | 79237 | RTHDR RECLAIM (KASLR LEAK); PIPE RECLAIM (KASLR LEAK) | 31<->32 | - | UNTRUSTED_RW_CLAIM | R/W was claimed before a triplet-ready invariant appeared; reclaim marker exists but does not prove independent primitive |
| 30 | 79447 | RTHDR RECLAIM (KASLR LEAK) | 31<->32, 25<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 31 | 79815 | RTHDR RECLAIM (KASLR LEAK) | 11<->32, 29<->32, 31<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 32 | 65813 | DANGLING-PTR KASLR LEAK | 31<->32, 32<->33 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 33 | 64805 | DANGLING-PTR KASLR LEAK | 25<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 34 | 64969 | DANGLING-PTR KASLR LEAK | 31<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 35 | 64969 | DANGLING-PTR KASLR LEAK | 31<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 36 | 65538 | DANGLING-PTR KASLR LEAK | 31<->32, 25<->32 | - | FAILED_AFTER_STAGE1 | failure markers appeared after Stage 1 |
| 37 | 65538 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |
| 38 | 63726 | - | - | - | NO_STAGE1 | Stage 1 did not reach race-won state |

## Luac0re-Derived Invariants Used

- Twin evidence is insufficient if it can be explained by self-read or same-round writes.
- Triplet readiness must appear before trusting later primitive claims.
- Reclaim markers are useful telemetry but not proof of kernel R/W by themselves.
- Critical runtime errors invalidate the tanda regardless of earlier milestones.
- Failure markers after Stage 1 mean the run remains blocked after alias capture.
- `[PT] phase ...` markers are authoritative for new invariant-guarded runs.
- Served `sha256` values are used to correlate logs with exact chain builds.

## Interpretation

Treat `UNTRUSTED_RW_CLAIM` as the historical false-positive bucket: useful for understanding heap behavior, but not acceptable as proof that TontoJB reached the Luac0re slow/fast primitive milestones.
