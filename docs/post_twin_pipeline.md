# Post-Twin Pipeline

## Goal

Make the path after twin capture explicit so later kernel R/W work can be built offline without re-deriving the chain each time.

## Current pipeline

1. `twins`
2. `triplet`
3. `kqueue_reclaim`
4. `kread_slow`
5. `kwrite_slow`
6. `kread_fast`
7. `kwrite_fast`
8. `payload`

## Current status

- `twins`: implemented and tracked in `poopsploit_chain.js`
- `kqueue_reclaim`: implemented and tracked in `poopsploit_chain.js`
- `triplet`: scaffolded with Luac0re-style repair helpers and pipeline state
- `kread_slow`: scaffolded with `uio/iov` descriptor buffers and placeholder entrypoint
- `kwrite_slow`: scaffolded with `uio/iov` descriptor buffers and placeholder entrypoint
- `kread_fast`: planned placeholder only
- `kwrite_fast`: planned placeholder only
- `payload`: planned placeholder only

## Design notes

- `triplet` now follows a Luac0re-style repair path structurally: start from a master twin and attempt to recover a third socket.
- `kqueue_reclaim` is the first concrete post-twin reclaim/leak stage in TontoJB today.
- `kread_slow` and `kwrite_slow` remain separate milestones, not implied by the leak.
- `kread_fast` and `kwrite_fast` should only be considered after a validated slow primitive exists.

## Logging contract

The runtime emits `[PT]` logs for post-twin phases:

- `phase -> in_progress`
- `phase -> ready`
- `phase -> failed`
- `phase -> planned`

And a summary line:

- `[PT] summary <label>: ...`

This lets the later pipeline be built incrementally without guessing which parts of the chain are already wired.
