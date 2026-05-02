# TontoJB Run Matrix

This matrix keeps the next live testing pass traceable. It is intentionally
diagnostic-first: a run can only be called progress when its log contains the
required invariant markers, not merely a marker echo or self-read pattern.

## Pre-run checks

Run these before attaching the proxy to a console session:

```sh
node --check exploit/poopsploit_chain.js
node --check exploit/inject_elfldr_automated.js
python3 -m py_compile proxy/proxy.py
python3 -m py_compile proxy/proxy_env.py
python3 -m py_compile tools/luacore_invariant_audit.py
```

## Runtime matrix

| Run | Proxy mode | Loader mode | Expected `[PT]` markers | Acceptable verdict |
|---|---|---|---|---|
| Baseline attach | main proxy | `LOADER_INJECT_MODE=session` | `twins -> ready` or clear failure | `STAGE1_ONLY` or better |
| KNOTE reclaim | main proxy | `session` | `reclaim -> ready/failed`, `kaslr -> ready/failed` | `RECLAIM_ONLY`, `PROMISING`, or clear failure |
| False-positive guard | main proxy | `session` | `slow_rw -> blocked reason=triplet_not_ready` | No `UNTRUSTED_RW_CLAIM` success treatment |
| Cache validation | main proxy | any | `[SUMMARY] chain_sha ...` changes with file edits | Matching served chain hash |
| Env probe | `proxy_env.py` | n/a | environment telemetry only | No exploit-success claim |

## Required live-log evidence

- `INYECTADO: poopsploit_chain.js (...) sha256=...` confirms exact served code.
- `[SUMMARY] chain_sha poopsploit_chain.js ...` gives a compact triage key.
- `[PT] phase twins -> ready` confirms a distinct master/slave pair.
- `[PT] phase reclaim -> ready|failed` records marker-based reclaim status.
- `[PT] phase triplet -> planned|ready|failed|blocked` prevents hidden assumptions.
- `[PT] phase slow_rw -> blocked reason=triplet_not_ready` prevents old false positives.
- `[PT] summary ...` must appear before accepting post-twin conclusions.

## Stop conditions

- Stop if `CRITICAL ERROR:` appears; classify the run as broken first.
- Stop if `twins -> failed`; do not interpret later marker reads.
- Stop if watchdog symptoms dominate logs; reduce workload before continuing.
- Stop if chain hash is missing; cache/proxy freshness is unproven.

## Audit command

```sh
python3 tools/luacore_invariant_audit.py --logs logos --output docs/otros/luacore_invariant_audit.md
```

Treat the generated report as the source of truth for historical runs.
