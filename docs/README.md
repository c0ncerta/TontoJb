# TontoJB documentation map

This directory contains research notes and operator-facing documentation for the TontoJB proof of concept. Keep polished explanations here; keep raw console dumps, local telemetry, and private run artifacts out of public commits.

## Core documents

| Document | Purpose |
|---|---|
| [`architecture.md`](architecture.md) | High-level architecture, repository layers, conceptual chain, and trust boundaries. |
| [`firmware-scope.md`](firmware-scope.md) | Firmware support matrix and documentation expectations for scoped claims. |
| [`troubleshooting.md`](troubleshooting.md) | Setup-level troubleshooting and publication hygiene checks. |
| [`research.md`](research.md) | Main research log: origin, sandbox capability testing, UAF evaluation, and implementation notes. |
| [`mitm_mcp_telemetry.md`](mitm_mcp_telemetry.md) | Local telemetry bridge for comparing proxy/Netflix runs through MCP tools. |
| [`run-matrix.md`](run-matrix.md) | Run comparison matrix for tracking reliability and failure modes. |
| [`post_twin_pipeline.md`](post_twin_pipeline.md) | Notes for stages after twin/triplet discovery. |
| [`webkit-probe-plan.md`](webkit-probe-plan.md) | WebKit probing plan and instrumentation notes. |

## Policy files

| Document | Purpose |
|---|---|
| [`policy/DISCLAIMER.md`](policy/DISCLAIMER.md) | Research-use boundaries, non-affiliation, and risk acknowledgement. |
| [`policy/SECURITY.md`](policy/SECURITY.md) | Responsible reporting scope and unsupported request categories. |
| [`policy/NOTICE.md`](policy/NOTICE.md) | Attribution, provenance, and third-party reference guidance. |
| [`policy/CONTRIBUTING.md`](policy/CONTRIBUTING.md) | Contribution boundaries and publication checklist. |
| [`policy/CHANGELOG.md`](policy/CHANGELOG.md) | Public research snapshot history. |

## Publication hygiene

- Do not commit `docs/logito/`; it is treated as raw log output.
- Do not commit `docs/otros/`; it is treated as local-only auxiliary notes.
- Prefer short, reproducible summaries over pasted proxy logs.
- Remove local absolute paths before publication.
- Redact private LAN addresses from any run excerpts you decide to keep.
- Keep credit and attribution wording consistent with the top-level README.

See [`GITHUB_RELEASE.md`](GITHUB_RELEASE.md) for the final upload checklist.
