# Firmware Scope

TontoJB is scoped to a documented PS5 firmware 11.60 research target under Netflix sandbox conditions. Firmware scope matters because syscall availability, sandbox policy, offsets, mitigations, and bug behavior can change across updates.

## Support matrix

| Firmware / target | Status | Notes |
|---|---:|---|
| PS5 11.60 | Documented research target | Offsets and behavior are described for this repository's current research stage. |
| Earlier PS5 firmware | Not claimed | Related public research may apply elsewhere, but this repository does not claim support. |
| Later PS5 firmware | Not claimed | Updates may patch relevant bugs or change sandbox behavior. |
| Non-PS5 platforms | Out of scope | The repository is not designed for other devices or services. |

## Scope rules

- Treat all technical claims as firmware-scoped unless a document explicitly says otherwise.
- Do not assume offsets, syscall behavior, or sandbox properties are portable across firmware.
- Do not publish firmware-shopping guidance or compatibility claims without reproducible, responsibly framed research notes.
- Do not treat this project as stable software or an end-user jailbreak package.

## Documentation expectations

New research notes should include:

1. Target firmware and hardware assumptions.
2. Delivery environment assumptions.
3. Whether observations are measured, inferred, or adapted from prior work.
4. Any privacy-sensitive log material removed or redacted before publication.

Unsupported firmware should be expected to fail safely, hang, or behave differently.
