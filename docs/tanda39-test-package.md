# Tanda39 Frozen Test Package

This package is the offline freeze point for the next live PS5 run. Do not use
the live result as proof unless the served chain fingerprint and `[PT]` markers
match this document.

## Freeze fingerprints

Generated before the live run from `TontoJB/`:

| File | SHA-256 |
|---|---|
| `exploit/poopsploit_chain.js` | `bec2cc5e9dd17cf6cea771706bc3037db8f89301ea912be3280c7a6282984e6f` |
| `exploit/inject_elfldr_automated.js` | `3486a5f99a79c6d6d6e16e67c4a890e04bd68b97507ce416ac5f2cf9d46371a5` |
| `proxy/proxy.py` | `8f0537ca44d45d0fb24a547a6c74906b0dfe88bb271aa97acdf3264994bac6d6` |
| `tools/luacore_invariant_audit.py` | `7ffdd9a9fb94f0ca3dab0e901912668bc62d087dcdbc49608515e82f96787ecc` |

Expected proxy short chain hash in live logs:

```text
[SUMMARY] chain_sha poopsploit_chain.js sha256=bec2cc5e9dd17cf6 bytes=...
```

Note: the proxy hashes served content after replacing `PLS_STOP_HARDCODING_IPS`.
The active chain currently has no such placeholder, so the served hash should
match the file hash above.

## Pre-run verification

Run from `TontoJB/` before starting mitmdump:

```bash
node --check exploit/poopsploit_chain.js
node --check exploit/inject_elfldr_automated.js
PYTHONDONTWRITEBYTECODE=1 python3 -B -m py_compile proxy/proxy.py proxy/proxy_env.py tools/luacore_invariant_audit.py tests/test_luacore_invariant_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_luacore_invariant_audit.py
python3 tools/luacore_invariant_audit.py --logs logos --output docs/luacore_invariant_audit.md
```

## Live run command

Run from `TontoJB/proxy/`:

```bash
mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 8080 --ssl-insecure --set connection_strategy=lazy --set termlog_verbosity=error
```

If the console cannot resolve the proxy host correctly, set `PROXY_PUBLIC_IP`
explicitly before starting mitmdump.

## Live log acceptance checklist

Required markers:

- `[SUMMARY] chain_sha poopsploit_chain.js sha256=bec2cc5e9dd17cf6 ...`
- `[1] === RACE WON! ===` or explicit Stage 1 failure evidence
- `[PT] phase twins -> ready` or `[PT] phase twins -> failed`
- `[PT] phase reclaim -> ready|failed|blocked`
- `[PT] phase triplet -> planned|ready|failed|blocked`
- `[PT] phase slow_rw -> blocked reason=triplet_not_ready` for the current knote path
- `[PT] summary ...`

Do **not** accept these as final success by themselves:

- `[K2] *** RECLAIM HIT! ...`
- `[K2] *** R/W ALIAS CONFIRMED ***`
- `[SUMMARY] R/W primitive established` if no triplet-ready invariant exists
- Any KASLR-looking pointer without the matching `[PT]` phase summary

## Expected current outcome

For the current knote path, the safest expected successful diagnostic outcome is:

```text
[PT] phase twins -> ready reason=distinct_master_slave_pair
[PT] phase reclaim -> ready reason=...
[PT] phase triplet -> planned reason=not_implemented_in_knote_path
[PT] phase slow_rw -> blocked reason=triplet_not_ready
[SUMMARY] R/W primitive blocked: triplet invariant missing
[PT] summary twins=ready reclaim=ready triplet=planned ... slow_rw=blocked
```

That means the guard is working. It is not a failure; it prevents the old
`tanda27`/`tanda29` false-positive interpretation.

## Post-run procedure

1. Save the full terminal/log output as `logos/tanda39.md`.
2. Re-run the auditor:

   ```bash
   python3 tools/luacore_invariant_audit.py --logs logos --output docs/luacore_invariant_audit.md
   ```

3. Classify the result from the audit report, not from a single exciting log line.

## Stop conditions

- Stop if `CRITICAL ERROR:` appears.
- Stop if the live chain hash is missing or differs unexpectedly.
- Stop if watchdog symptoms dominate before Stage 1 stabilizes.
- Stop if `twins -> failed`; later reads are not trustworthy.
