# WebKit Probe Harness Plan

Goal: use the stable Netflix-N-Hack page as a repeatable observation point for
WebKit/Netflix runtime research without running the kernel chain, heap sprays,
or crash-oriented fuzzing.

## Principle

Keep this lane separate from `poopsploit_chain.js`.

- `poopsploit_chain.js` remains the kernel-chain lane.
- `webkit_probe_harness.js` is the stable WebKit/Netflix runtime lane.
- MITM logs become the real-time telemetry surface.
- IDA/MCP analysis comes later, only after a reproducible anomaly appears.

## Files

- `exploit/webkit_probe_harness.js`: passive JS harness served into the Netflix error page.
- `proxy/proxy.py`: supports `TJB_LOADER_PAYLOAD=webkit_probe` and `/js/webkit_probe_harness.js`.
- `docs/webkit-probe-plan.md`: this workflow.

## Safe-mode command

Run from `TontoJB/proxy/`:

```bash
TJB_LOADER_PAYLOAD=webkit_probe mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 8080 --ssl-insecure --set connection_strategy=lazy --set termlog_verbosity=error
```

Expected proxy startup line:

```text
[+] Loader payload: webkit_probe
```

Expected delivery marker:

```text
[SUMMARY] loader_payload webkit_probe_harness.js sha256=... bytes=...
```

Expected page/log marker:

```text
[WK] phase stable -> ready reason=passive_webkit_probe_loaded
```

## Controls inside the stable page

- Triangle / F1 / Up: environment snapshot.
- Square / Enter / Space: light probes.
- Circle / Escape: stop heartbeat.
- If console access exists: `globalThis.TJB_WK.runAll()`.

## Current probe scope

These are intentionally non-destructive:

- Environment surface map: `navigator`, `location`, `document`, selected `nrdp` objects.
- Feature presence: `WebAssembly`, `SharedArrayBuffer`, `BigInt`, `Proxy`, timers.
- Light typed-array allocation and read/write sanity check.
- Small `Map` churn sanity check.
- Timer delay measurement.
- Optional `nrdp.gibbon.garbageCollect()` call if the app exposes it.
- Event-loop heartbeat and max-lag tracking.

## Things this harness must not do

- No syscalls.
- No ROP/JOP.
- No kernel UAF path.
- No aggressive heap spray.
- No crash-loop or auto-blacklist fuzzing.
- No malformed input generator until a separate plan is written.

## How to use results

Look for reproducible `[WK]` anomalies, for example:

- A specific object path exists only on PS5 Netflix.
- A feature is present but behaves differently than normal WebKit.
- Timer/GC behavior changes after a specific UI action.
- The harness page remains stable but a specific passive probe causes reload.
- A repeated error message appears with the same action sequence.

Only after a reproducible anomaly exists should we pivot to IDA Pro/MCP:

1. Freeze the exact harness SHA and log snippet.
2. Identify the suspected Netflix/WebKit/native surface.
3. Open matching binary/module in IDA.
4. Use MCP-assisted static analysis to explain the observed behavior.
5. Add a new passive probe to confirm or falsify the hypothesis.

## Log labels

- `[WK] phase stable -> ready`: harness loaded and stable.
- `[WK] env ...`: environment key/value observation.
- `[WK] probe ...`: one safe probe result.
- `[WK] heartbeat ...`: event-loop health while parked.
- `[WK] summary ...`: final/periodic state summary.

## Recommended first live pass

1. Start proxy with `TJB_LOADER_PAYLOAD=webkit_probe`.
2. Open Netflix until the WebKit probe page appears.
3. Wait two heartbeat cycles to confirm stability.
4. Press Triangle/Up once; capture environment snapshot.
5. Press Square once; run light probes.
6. Leave it parked for 5-10 minutes.
7. Save output as `logos/webkit_probe_tanda1.md`.

Success means the page stays alive and logs remain readable through MITM. It
does not mean a vulnerability exists yet.
