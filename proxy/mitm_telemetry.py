"""Small JSONL telemetry sink for the TontoJB mitmproxy scripts.

The proxy must keep running even if telemetry is unavailable, so every public
helper in this module is best-effort and swallows I/O failures.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import threading
from typing import Any, Optional


_DEFAULT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "LOGS", "mitm_events.jsonl")
)
TELEMETRY_PATH = os.environ.get("TJB_MITM_TELEMETRY_PATH", _DEFAULT_PATH)
TELEMETRY_ENABLED = os.environ.get("TJB_MITM_TELEMETRY", "on").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
MAX_TEXT = int(os.environ.get("TJB_MITM_TELEMETRY_MAX_TEXT", "1200"))
_LOCK = threading.Lock()


def telemetry_status() -> str:
    if not TELEMETRY_ENABLED:
        return "disabled"
    return f"enabled path={TELEMETRY_PATH}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _clean_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        if len(value) > MAX_TEXT:
            return value[:MAX_TEXT] + f"…<truncated:{len(value) - MAX_TEXT}>"
        return value
    if isinstance(value, dict):
        return {str(k): _clean_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_clean_value(v) for v in value]
    return str(value)


def emit_event(event: str, **fields: Any) -> None:
    """Append one JSONL event; never raise into mitmproxy."""
    if not TELEMETRY_ENABLED:
        return

    record = {"ts": _now_iso(), "event": event}
    record.update({key: _clean_value(value) for key, value in fields.items()})

    try:
        os.makedirs(os.path.dirname(TELEMETRY_PATH), exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with _LOCK:
            with open(TELEMETRY_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        return


def emit_ps5_log(log_msg: str, client_ip: str, channel: Optional[str] = None) -> None:
    emit_event(
        "ps5_log",
        client_ip=client_ip,
        channel=channel,
        marker=_extract_marker(log_msg),
        message=log_msg,
    )


def emit_milestone(key: str, line: str, source: str = "ps5_log") -> None:
    emit_event("milestone", key=key, marker=line, source=source)


def emit_route(
    route: str,
    path: str,
    client_ip: str,
    status_code: int,
    content_type: str,
    byte_len: int,
    source_path: Optional[str] = None,
    note: Optional[str] = None,
) -> None:
    emit_event(
        "route_served",
        route=route,
        path=path,
        client_ip=client_ip,
        status_code=status_code,
        content_type=content_type,
        byte_len=byte_len,
        source_path=source_path,
        note=note,
    )


def emit_route_error(route: str, path: str, client_ip: str, status_code: int, error: str) -> None:
    emit_event(
        "route_error",
        route=route,
        path=path,
        client_ip=client_ip,
        status_code=status_code,
        error=error,
    )


def emit_block(kind: str, hostname: str, method: str, status_code: Optional[int] = None) -> None:
    emit_event("blocked", kind=kind, hostname=hostname, method=method, status_code=status_code)


def _extract_marker(log_msg: str) -> Optional[str]:
    for marker in ("[SUMMARY]", "[PT]", "[S0]", "[S1]", "[TJB]", "[FUZZ]"):
        if marker in log_msg:
            return marker
    return None
