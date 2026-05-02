#!/usr/bin/env python3
"""MCP stdio server exposing TontoJB mitmproxy telemetry JSONL.

This is intentionally stdlib-only: Claude Code/OpenCode can launch it directly
without creating a Python package or installing an MCP SDK.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
import re
import sys
from collections import Counter, deque
from typing import Any, BinaryIO, Iterable, Optional


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_TELEMETRY_PATH = os.path.join(ROOT, "LOGS", "mitm_events.jsonl")
PROTOCOL_VERSION = "2024-11-05"
DEBUG_PATH = os.environ.get("TJB_MITM_MCP_DEBUG_PATH", "")
_TRANSPORT_MODE = "headers"
RUN_START_ROUTES = {"lruderrorpage-loader", "lruderrorpage-webkit-probe"}
RUN_SIGNAL_EVENTS = {"ps5_log", "milestone", "post_twin", "route_served", "route_error"}


def debug(message: str) -> None:
    if not DEBUG_PATH:
        return
    try:
        with open(DEBUG_PATH, "a", encoding="utf-8") as f:
            f.write(message + "\n")
    except OSError:
        return


def telemetry_path(args: argparse.Namespace) -> str:
    return os.path.abspath(
        args.telemetry_path
        or os.environ.get("TJB_MITM_TELEMETRY_PATH")
        or DEFAULT_TELEMETRY_PATH
    )


def _event_allowed(row: dict[str, Any], event: Optional[str], exclude_events: Optional[Iterable[str]]) -> bool:
    row_event = str(row.get("event", ""))
    if event and row_event != event:
        return False
    if exclude_events and row_event in set(exclude_events):
        return False
    return True


def read_events(
    path: str,
    limit: int = 200,
    event: Optional[str] = None,
    exclude_events: Optional[Iterable[str]] = None,
) -> list[dict[str, Any]]:
    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000
    if not os.path.exists(path):
        return []

    rows: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not _event_allowed(row, event, exclude_events):
                    continue
                rows.append(row)
    except OSError as exc:
        return [{"event": "mcp_read_error", "error": str(exc), "path": path}]
    return list(rows)


def search_events(
    path: str,
    pattern: str,
    limit: int = 100,
    event: Optional[str] = None,
    exclude_events: Optional[Iterable[str]] = None,
) -> list[dict[str, Any]]:
    if not pattern:
        return []
    try:
        needle = re.compile(pattern, re.IGNORECASE)
    except re.error:
        needle = re.compile(re.escape(pattern), re.IGNORECASE)

    matches: deque[dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
    for row in read_events(path, limit=5000, event=event, exclude_events=exclude_events):
        haystack = json.dumps(row, ensure_ascii=False, sort_keys=True)
        if needle.search(haystack):
            matches.append(row)
    return list(matches)


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _seconds_between(left: Optional[datetime], right: Optional[datetime]) -> Optional[float]:
    if left is None or right is None:
        return None
    return (right - left).total_seconds()


def _run_record(client_ip: str, index: int, row: dict[str, Any], explicit: bool) -> dict[str, Any]:
    return {
        "run_id": f"{client_ip or 'unknown'}:{index:04d}",
        "client_ip": client_ip or "unknown",
        "start_ts": row.get("ts"),
        "end_ts": row.get("ts"),
        "start_reason": "loader-route" if explicit else "inferred-idle-or-first-event",
        "duration_seconds": 0.0,
        "events": 0,
        "counts_by_event": {},
        "counts_by_route": {},
        "route_sequence": [],
        "stage_signals": [],
        "last_event": None,
    }


def _add_to_run(run: dict[str, Any], row: dict[str, Any]) -> None:
    event = str(row.get("event", "unknown"))
    route = row.get("route")
    run["events"] += 1
    run["end_ts"] = row.get("ts") or run["end_ts"]
    run["last_event"] = row
    run["counts_by_event"][event] = run["counts_by_event"].get(event, 0) + 1
    if route:
        run["counts_by_route"][route] = run["counts_by_route"].get(route, 0) + 1
    if event in {"route_served", "route_error"}:
        run["route_sequence"].append(
            {
                "ts": row.get("ts"),
                "route": route,
                "status_code": row.get("status_code"),
                "byte_len": row.get("byte_len"),
                "note": row.get("note"),
            }
        )
    message = str(row.get("message", row.get("marker", "")))
    if event in {"milestone", "post_twin"} or "[SUMMARY]" in message or "[PT]" in message or "won=true" in message:
        run["stage_signals"].append(
            {
                "ts": row.get("ts"),
                "event": event,
                "key": row.get("key"),
                "marker": row.get("marker"),
                "message": message,
            }
        )
    start = _parse_ts(run.get("start_ts"))
    end = _parse_ts(run.get("end_ts"))
    duration = _seconds_between(start, end)
    if duration is not None:
        run["duration_seconds"] = round(max(0.0, duration), 3)


def build_runs(path: str, limit: int = 5000, idle_seconds: float = 90.0, include_blocked: bool = False) -> list[dict[str, Any]]:
    exclude = None if include_blocked else ["blocked"]
    rows = read_events(path, limit=limit, exclude_events=exclude)
    rows = [row for row in rows if str(row.get("event", "")) in RUN_SIGNAL_EVENTS]
    rows.sort(key=lambda row: row.get("ts", ""))

    active: dict[str, dict[str, Any]] = {}
    last_ts: dict[str, Optional[datetime]] = {}
    counters: Counter[str] = Counter()
    runs: list[dict[str, Any]] = []

    for row in rows:
        client_ip = str(row.get("client_ip") or "unknown")
        route = str(row.get("route") or "")
        event = str(row.get("event") or "")
        current_ts = _parse_ts(row.get("ts"))
        elapsed = _seconds_between(last_ts.get(client_ip), current_ts)
        explicit_start = event == "route_served" and route in RUN_START_ROUTES
        idle_start = client_ip not in active or (elapsed is not None and elapsed > idle_seconds)

        if explicit_start or idle_start:
            counters[client_ip] += 1
            run = _run_record(client_ip, counters[client_ip], row, explicit_start)
            runs.append(run)
            active[client_ip] = run

        _add_to_run(active[client_ip], row)
        last_ts[client_ip] = current_ts

    return runs


def build_summary(path: str, limit: int = 1000) -> dict[str, Any]:
    rows = read_events(path, limit=limit)
    by_event = Counter(row.get("event", "unknown") for row in rows)
    by_route = Counter(
        row.get("route", "unknown") for row in rows if row.get("event") == "route_served"
    )
    last_by_event: dict[str, dict[str, Any]] = {}
    milestones: list[dict[str, Any]] = []
    post_twin: list[dict[str, Any]] = []
    route_sequence: list[dict[str, Any]] = []
    stage_signals: list[dict[str, Any]] = []
    for row in rows:
        event = str(row.get("event", "unknown"))
        last_by_event[event] = row
        if event == "milestone":
            milestones.append(row)
        if event == "post_twin" or "[PT]" in str(row.get("message", "")):
            post_twin.append(row)
        if event == "route_served":
            route_sequence.append(
                {
                    "ts": row.get("ts"),
                    "client_ip": row.get("client_ip"),
                    "route": row.get("route"),
                    "status_code": row.get("status_code"),
                    "byte_len": row.get("byte_len"),
                    "note": row.get("note"),
                }
            )
        message = str(row.get("message", row.get("marker", "")))
        if event in {"milestone", "post_twin"} or "[SUMMARY]" in message or "[PT]" in message or "won=true" in message:
            stage_signals.append(
                {
                    "ts": row.get("ts"),
                    "event": event,
                    "client_ip": row.get("client_ip"),
                    "key": row.get("key"),
                    "marker": row.get("marker"),
                    "message": message,
                }
            )

    return {
        "path": path,
        "exists": os.path.exists(path),
        "events_seen": len(rows),
        "counts_by_event": dict(by_event),
        "counts_by_route": dict(by_route),
        "latest_by_event": last_by_event,
        "latest_milestones": milestones[-20:],
        "latest_post_twin": post_twin[-20:],
        "latest_route_sequence": route_sequence[-30:],
        "latest_stage_signals": stage_signals[-40:],
        "latest_runs": build_runs(path, limit=limit)[-10:],
    }


def clear_events(path: str, confirm: bool) -> dict[str, Any]:
    if not confirm:
        return {"cleared": False, "reason": "Pass confirm=true to clear telemetry."}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").close()
    return {"cleared": True, "path": path}


TOOLS = [
    {
        "name": "mitm_recent_events",
        "description": "Return the most recent TontoJB mitmproxy telemetry events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 50},
                "event": {"type": "string", "description": "Optional event type filter."},
                "exclude_events": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional event types to omit, e.g. ['blocked'].",
                },
            },
        },
    },
    {
        "name": "mitm_search_events",
        "description": "Search recent telemetry events by regex or substring.",
        "inputSchema": {
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
                "event": {"type": "string", "description": "Optional event type filter."},
                "exclude_events": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional event types to omit, e.g. ['blocked'].",
                },
            },
        },
    },
    {
        "name": "mitm_summary",
        "description": "Summarize latest milestones, route serves, and event counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 1000},
            },
        },
    },
    {
        "name": "mitm_runs",
        "description": "Group telemetry events into Netflix/proxy runs by client and time window.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 5000},
                "idle_seconds": {"type": "number", "minimum": 1, "maximum": 3600, "default": 90},
                "include_blocked": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "mitm_clear_events",
        "description": "Clear the telemetry JSONL file after explicit confirmation.",
        "inputSchema": {
            "type": "object",
            "required": ["confirm"],
            "properties": {"confirm": {"type": "boolean"}},
        },
    },
]


def tool_result(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            }
        ]
    }


def handle_request(message: dict[str, Any], path: str) -> Optional[dict[str, Any]]:
    method = message.get("method")
    msg_id = message.get("id")
    debug(f"request method={method} id={msg_id}")

    if msg_id is None:
        return None

    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "tontojb-mitm-telemetry", "version": "0.1.0"},
                },
            }
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = message.get("params", {}) or {}
            name = params.get("name")
            args = params.get("arguments", {}) or {}
            if name == "mitm_recent_events":
                result = read_events(path, int(args.get("limit", 50)), args.get("event"), args.get("exclude_events"))
            elif name == "mitm_search_events":
                result = search_events(path, str(args.get("pattern", "")), int(args.get("limit", 50)), args.get("event"), args.get("exclude_events"))
            elif name == "mitm_summary":
                result = build_summary(path, int(args.get("limit", 1000)))
            elif name == "mitm_runs":
                result = build_runs(
                    path,
                    int(args.get("limit", 5000)),
                    float(args.get("idle_seconds", 90.0)),
                    bool(args.get("include_blocked", False)),
                )
            elif name == "mitm_clear_events":
                result = clear_events(path, bool(args.get("confirm", False)))
            else:
                raise ValueError(f"Unknown tool: {name}")
            return {"jsonrpc": "2.0", "id": msg_id, "result": tool_result(result)}
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32000, "message": str(exc)},
        }


def read_frame(stream: BinaryIO) -> Optional[dict[str, Any]]:
    global _TRANSPORT_MODE
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        stripped = line.strip()
        if stripped.startswith(b"{"):
            _TRANSPORT_MODE = "jsonl"
            debug("read jsonl")
            return json.loads(stripped.decode("utf-8"))
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("ascii", errors="replace").partition(":")
        headers[key.strip().lower()] = value.strip()

    content_length = int(headers.get("content-length", "0"))
    if content_length <= 0:
        return None
    body = stream.read(content_length)
    debug(f"read content_length={content_length}")
    return json.loads(body.decode("utf-8"))


def write_frame(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if _TRANSPORT_MODE == "jsonl":
        stream.write(body + b"\n")
    else:
        stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    stream.flush()
    debug(f"wrote mode={_TRANSPORT_MODE} id={message.get('id')} keys={list(message.keys())}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry-path", help="Path to mitm_events.jsonl")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    path = telemetry_path(args)
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    debug(f"started path={path}")
    while True:
        message = read_frame(stdin)
        if message is None:
            return 0
        response = handle_request(message, path)
        if response is not None:
            write_frame(stdout, response)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
