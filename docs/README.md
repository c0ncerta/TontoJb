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

## Audit and comparison notes

| Document | Purpose |
|---|---|
| [`luac0re_vs_tontojb.md`](luac0re_vs_tontojb.md) | Comparison between Luac0re assumptions and this Netflix-based path. |
| [`luacore_invariant_audit.md`](luacore_invariant_audit.md) | Invariant audit notes for Luac0re-derived behavior. |
| [`luacore_invariant_audit_usage.md`](luacore_invariant_audit_usage.md) | Usage notes for the invariant audit helper. |
| [`parametros_y_limites.md`](parametros_y_limites.md) | Spanish notes on parameters, limits, and tested boundaries. |
| [`contenido_importante.md`](contenido_importante.md) | Spanish scratch/research notes worth reviewing before publication. |
| [`tanda39-test-package.md`](tanda39-test-package.md) | Packaged notes from a specific test run; review before including publicly. |

## Publication hygiene

- Do not commit `docs/logito/`; it is treated as raw log output.
- Prefer short, reproducible summaries over pasted proxy logs.
- Remove local absolute paths before publication.
- Redact private LAN addresses from any run excerpts you decide to keep.
- Keep credit and attribution wording consistent with the top-level README.

See [`GITHUB_RELEASE.md`](GITHUB_RELEASE.md) for the final upload checklist.
