# Luac0re vs TontoJB

## Goal

Document what Luac0re does, what TontoJB already has, and what is still missing.

## Environment difference

- **Luac0re**: Lua runtime, persistent worker infrastructure, less tied to Netflix page lifecycle.
- **TontoJB**: Netflix JS runtime, event-loop sensitivity, watchdog-style lag pressure, proxy-delivered payloads.

## Phase mapping

| Luac0re Phase | Luac0re Mechanism | TontoJB Current State | Notes |
|---|---|---|---|
| Twins | `find_twins()` over IPv6 rthdr spray | Implemented in `poopsploit_chain.js` | Stable enough to win Stage 1 repeatedly |
| Triplet | `find_triplet()` + `repair_triplets()` | Scaffolded in `poopsploit_chain.js` and `luacore_post_twin_equiv.js` | Not yet wired into the main chain |
| Kqueue reclaim | reclaim freed rthdr with `kqueue()` | Implemented in `stage3_kqueue_reclaim()` | First concrete post-twin leak stage |
| Slow kread | `uio/iov` race via workers/socketpairs | Scaffolded in both files | Descriptor buffers exist, primitive not wired |
| Slow kwrite | `uio/iov` write path | Scaffolded in both files | Same status as kread |
| Pipe leak | leak master/victim pipe pointers | Placeholder only in `luacore_post_twin_equiv.js` | Not wired in main chain |
| Pipe corruption | overwrite victim pipe buffer | Placeholder only in `luacore_post_twin_equiv.js` | Future bridge to fast rw |
| Fast kread/kwrite | pipe-based primitive | Planned only | Depends on slow rw first |
| Jailbreak payload | creds/sandbox patch path | Planned only | Out of scope until fast rw is real |

## What Luac0re is especially good at

1. Short twin scan
- `64` IPv6 probes
- `MAX_ROUNDS_TWIN = 10`
- `sched_yield()` during detection

2. Treating triplet repair as its own stage
- Twin is not considered enough.
- Luac0re repairs or re-finds missing triplet entries aggressively.

3. Building a slow primitive before chasing a fast one
- `kread_slow`
- `kwrite_slow`
- only then `pipe` corruption

4. Worker-based infrastructure
- `create_worker_sync`
- `signal_workers`
- `wait_workers`
- persistent `uio/iov` workers

## What matters more in Netflix/TontoJB

1. Keep scans short.
2. Avoid long monolithic loops.
3. Prefer retries over one giant attempt.
4. Keep the main chain small and move experiments to separate files.

## Recommended use of the separate experiment file

`exploit/luacore_post_twin_equiv.js` should be used for:

- experimenting with triplet logic
- experimenting with slow rw scaffolding
- comparing Luac0re assumptions against Netflix runtime behavior

It should not replace the working main chain until a sub-stage is validated.
