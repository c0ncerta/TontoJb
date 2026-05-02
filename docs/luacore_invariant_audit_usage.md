# Luac0re Invariant Audit Usage

This is an offline log-audit workflow for `TontoJB/logos/tanda*.md`.

It intentionally does **not** modify or execute the exploit chain. Its job is to
separate real Luac0re-style progress from marker-only or self-read false positives.

## Run

From `TontoJB/`:

```bash
python3 tools/luacore_invariant_audit.py --logs logos --output docs/luacore_invariant_audit.md
```

## Offline fixture test

Before trusting changes to the audit rules, run the PS5-free fixture suite:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_luacore_invariant_audit.py
```

The fixture suite covers:

- no Stage 1 win (`NO_STAGE1`)
- historical marker-only R/W false positive (`UNTRUSTED_RW_CLAIM`)
- new `[PT] slow_rw -> blocked` guard (`RECLAIM_ONLY`)
- triplet-ready plus reclaim evidence (`PROMISING`)
- critical runtime error (`BROKEN`)
- self-alias rejection (`REJECT_SELF_ALIAS`)

## Verdicts

- `NO_STAGE1`: the tanda never reached a trustworthy race-won milestone.
- `FAILED_AFTER_STAGE1`: Stage 1 won, then later phases failed.
- `UNTRUSTED_RW_CLAIM`: a reclaim/RW claim exists without triplet-ready evidence.
- `BROKEN`: a critical runtime error invalidated the tanda.
- `PROMISING`: triplet-ready and reclaim evidence coexist.

## Current interpretation

The current `logos` audit flags `tanda27` and `tanda29` as
`UNTRUSTED_RW_CLAIM`, matching the working hypothesis that their apparent R/W
success was based on the false-twin/self-read pattern rather than a validated
Luac0re-style primitive.

The audit also shows the later `DANGLING-PTR`/knote path returns to a safer
direction, but remains blocked after Stage 1 in the available logs.
