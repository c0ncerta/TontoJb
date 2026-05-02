# mitmproxy telemetry MCP

This adds a local telemetry bridge for the Netflix/PS5 proxy flow:

```text
PS5 / Netflix app
  -> mitmproxy proxy.py
  -> TontoJB/LOGS/mitm_events.jsonl
  -> TontoJB/tools/mitm_mcp_server.py
  -> Claude Code / OpenCode MCP tools
```

The proxy remains the runtime source of truth. The MCP server only reads the
JSONL file, so it can be restarted without touching the active mitmdump process.

## Run mitmproxy

From `TontoJB/proxy/`:

```bash
mitmdump -s proxy.py \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --ssl-insecure \
  --set connection_strategy=lazy \
  --set termlog_verbosity=error
```

Telemetry is enabled by default and writes to:

```text
TontoJB/LOGS/mitm_events.jsonl
```

Optional knobs:

```bash
export TJB_MITM_TELEMETRY=off
export TJB_MITM_TELEMETRY_PATH=/tmp/tontojb-mitm-events.jsonl
export TJB_MITM_TELEMETRY_MAX_TEXT=1200
```

## MCP command

Use this command as the MCP stdio server:

```bash
python3 tools/mitm_mcp_server.py
```

If you use a custom JSONL path, pass the same path to the MCP server:

```bash
python3 tools/mitm_mcp_server.py \
  --telemetry-path /tmp/tontojb-mitm-events.jsonl
```

## Claude Code / OpenCode config shape

For OpenCode, use the current `mcp` config key:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "tontojb-mitm": {
      "type": "local",
      "command": [
        "python3",
        "tools/mitm_mcp_server.py"
      ],
      "enabled": true
    }
  }
}
```

For Claude Code, use:

```bash
claude mcp add tontojb-mitm -- python3 tools/mitm_mcp_server.py
```

## Exposed MCP tools

- `mitm_recent_events`
  - Args: `limit`, optional `event`, optional `exclude_events`
  - Use for the latest raw JSONL events; pass `exclude_events: ["blocked"]`
    when TLS/HTTP block noise hides useful PS5 logs.
- `mitm_search_events`
  - Args: `pattern`, optional `limit`, optional `event`, optional `exclude_events`
  - Use for `[SUMMARY]`, `[PT]`, `poopsploit_chain`, or failure searches.
- `mitm_summary`
  - Args: optional `limit`
  - Use for latest milestones, latest post-twin lines, route counts, latest
    route sequence, latest stage signals, and latest grouped runs.
- `mitm_runs`
  - Args: optional `limit`, optional `idle_seconds`, optional `include_blocked`
  - Groups telemetry into Netflix/proxy executions by `client_ip`, explicit
    loader routes, and idle gaps. Use this to compare one launch against the
    next without reading raw JSONL.
- `mitm_clear_events`
  - Args: `confirm: true`
  - Use before a fresh PS5 run.

## Useful prompts once connected

```text
Use the tontojb-mitm MCP server. Summarize the latest PS5 run and tell me if
poopsploit_chain.js was served after the loader.
```

```text
Search mitm telemetry for [SUMMARY] and [PT]. If Stage 2 failed, inspect
TontoJB/exploit/poopsploit_chain.js and propose the smallest code change.
```

```text
Clear mitm telemetry, wait for my next Netflix launch, then compare the fresh
route_served events to the expected loader -> poopsploit_chain sequence.
```

## Event types

- `ps5_log`: normalized `/log?msg=...` messages from the console.
- `milestone`: proxy-derived `[SUMMARY]` checkpoints.
- `post_twin`: `[PT]` pipeline logs.
- `route_served`: local payloads served by proxy route mapping.
- `route_error`: local payload route failures.
- `blocked`: HTTP/TLS block events from `hosts.txt` handling.

## Triage workflow

1. Start fresh when you want a clean run:

   ```text
   Use tontojb-mitm. Call mitm_clear_events with confirm=true.
   ```

2. Launch Netflix and wait for route/log activity.

3. Ask for the high-level state:

   ```text
   Use tontojb-mitm. Call mitm_summary with limit=1500.
   ```

4. If recent events are mostly telemetry blocking, remove the noise:

   ```text
   Use tontojb-mitm. Call mitm_recent_events with limit=80 and exclude_events=["blocked"].
   ```

5. For the current Stage 1 gap, search targeted stage signals:

   ```text
   Use tontojb-mitm. Search for "Stage 2|STAGE 2|\\[PT\\]|won=true|poopsploit_chain".
   ```

6. Interpret the result before editing code:

   - `loader -> poopsploit_chain` present means routing worked.
   - repeated `won=true` but no `Stage 2` means the gap is after Stage 1 logs.
   - no `[PT]` means the post-twin pipeline did not start or did not log.
   - mostly `blocked` events means query with `exclude_events=["blocked"]`.

## Run grouping workflow

Use `mitm_runs` when you need a per-launch view instead of one global timeline:

```text
Use tontojb-mitm. Call mitm_runs with limit=5000 and idle_seconds=90.
```

Each run contains:

- `run_id`: stable diagnostic ID in the form `client_ip:NNNN`.
- `client_ip`: PS5/client address observed by mitmproxy.
- `start_reason`: `loader-route` for explicit loader starts, otherwise an
  inferred idle/first-event boundary.
- `duration_seconds`: observed span from first to last grouped event.
- `counts_by_event`: quick composition of the run.
- `counts_by_route`: local proxy routes served in that run.
- `route_sequence`: ordered local route evidence.
- `stage_signals`: `[SUMMARY]`, `[PT]`, and `won=true` signal lines.

For the current Stage 1 gap, the expected diagnostic pattern is:

```text
route_sequence: lruderrorpage-loader -> poopsploit_chain
stage_signals: Stage 1 entered, won=true attempts
missing: Stage 2 / [PT]
```

If two Netflix launches merge into one run, lower `idle_seconds`. If one launch
splits into several runs, raise `idle_seconds`.

## Safety notes

- Events are metadata-first; large messages are truncated.
- Telemetry failures are swallowed so mitmproxy does not crash.
- The MCP server only reads/clears the JSONL file; code edits still happen via
  Claude Code/OpenCode normal file tools after analysis.
