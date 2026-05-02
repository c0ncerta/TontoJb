# TontoJB Architecture Overview

This document describes the repository architecture at a high level. It is intended as a map for reviewers and researchers, not as an operational exploitation guide.

## System model

```text
Research workstation
  -> local mitmproxy route replacement
  -> Netflix WebKit JavaScript delivery path
  -> syscall and sandbox capability probes
  -> kernel research chain experiments
  -> local telemetry and documentation review
```

## Repository layers

| Layer | Repository area | Purpose |
|---|---|---|
| Delivery | `proxy/` | Local mitmproxy scripts and host-routing configuration. |
| Loader and chain | `exploit/` | JavaScript components used by the documented research path. |
| Payload experiments | `payloads/` | Research payload assets and loader experiments. |
| Firmware data | `offsets/` | Firmware-scoped offset material. |
| Analysis | `tools/`, `tests/` | Local analysis helpers and regression checks. |
| Documentation | `README.md`, `docs/` | Public explanation, scope, telemetry notes, and run summaries. |

## Conceptual chain

TontoJB documents a narrow PS5 firmware 11.60 research path through the Netflix sandbox. At a conceptual level, the chain studies how a local delivery route can load JavaScript into the Netflix WebKit environment, validate available primitives, evaluate a `sys_netcontrol` UCred UAF path, shape kernel heap state through IPv6-related objects, and reason about kernel read/write and credential-patching research outcomes.

The repository intentionally keeps public architecture documentation descriptive. Firmware-specific assumptions, timing sensitivity, runtime state, and sandbox behavior can change across environments and patches.

## Trust boundaries

- The research workstation and local proxy are outside the console.
- Netflix WebKit execution is constrained by the app sandbox.
- Kernel-facing primitives are firmware-scoped and should not be treated as portable.
- Runtime logs can contain private network details and should remain local.

## Review guidance

When reviewing architecture changes, check that the change:

- Preserves firmware scope.
- Avoids publishing private logs or local network identifiers.
- Improves understanding without adding consumer jailbreak instructions.
- Keeps upstream attribution and repository-specific adaptation boundaries clear.
