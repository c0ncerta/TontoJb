# TontoJB documentation map

This directory contains research notes and operator-facing documentation for the TontoJB proof of concept. Keep polished explanations here; keep raw console dumps, local telemetry, and private run artifacts out of public commits.

## Core documents

| Document | Purpose |
|---|---|
| [`research.md`](research.md) | Main research log: origin, sandbox capability testing, UAF evaluation, and implementation notes. |
| [`mitm_mcp_telemetry.md`](mitm_mcp_telemetry.md) | Local telemetry bridge for comparing proxy/Netflix runs through MCP tools. |
| [`run-matrix.md`](run-matrix.md) | Run comparison matrix for tracking reliability and failure modes. |
| [`post_twin_pipeline.md`](post_twin_pipeline.md) | Notes for stages after twin/triplet discovery. |
| [`webkit-probe-plan.md`](webkit-probe-plan.md) | WebKit probing plan and instrumentation notes. |

## Publication hygiene

- Do not commit `docs/logito/`; it is treated as raw log output.
- Do not commit `docs/otros/`; it is treated as local-only auxiliary notes.
- Prefer short, reproducible summaries over pasted proxy logs.
- Remove local absolute paths before publication.
- Redact private LAN addresses from any run excerpts you decide to keep.
- Keep credit and attribution wording consistent with the top-level README.

See [`GITHUB_RELEASE.md`](GITHUB_RELEASE.md) for the final upload checklist.
