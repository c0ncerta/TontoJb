from mitmproxy import http
from mitmproxy.proxy.layers import tls
import hashlib
import os
import threading
import re
import time
from typing import Optional

import mitm_telemetry as telemetry

# --- AUTO BLACKLIST STATE ---
last_tried_sys = None
last_fuzz_info = None  # Stores "sys(624) arg1=0x4141..." for fuzzing phases
sys_lock = threading.Lock()
poopsploit_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "main.js")
fuzz_log_path = os.path.join(os.path.dirname(__file__), "..", "..", "DOCS", "fuzz_crashes.log")
AUTOBLACKLIST_MODE = os.environ.get("AUTOBLACKLIST_MODE", "off").strip().lower()
AUTOBLACKLIST_ENABLED = AUTOBLACKLIST_MODE == "fuzz"

# Fuzzing targets that should be logged but not auto-blacklisted.
FUZZ_TARGETS = {649, 622, 522}

def auto_blacklist(sys_num: int) -> None:
    """Append crashing syscall numbers into poopsploit SKIP list."""
    global last_fuzz_info
    if not AUTOBLACKLIST_ENABLED:
        return

    if sys_num in FUZZ_TARGETS:
        msg = f"\n\033[93m[FUZZ-CRASH]\033[0m sys({sys_num}) crashed but is a FUZZ TARGET - NOT blacklisting!"
        if last_fuzz_info:
            msg += f"\n\033[93m[FUZZ-CRASH]\033[0m Args: {last_fuzz_info}"
        print(msg)
        try:
            os.makedirs(os.path.dirname(fuzz_log_path), exist_ok=True)
            with open(fuzz_log_path, "a") as f:
                import datetime
                f.write(f"[{datetime.datetime.now()}] CRASH sys({sys_num}) | {last_fuzz_info or 'unknown args'}\n")
        except Exception:
            pass
        return

    try:
        with open(poopsploit_path, "r", encoding="utf-8") as f:
            content = f.read()

        if f"    {sys_num}," in content or f"    {sys_num} " in content:
            return

        if "var SKIP = [" in content:
            new_content = content.replace("var SKIP = [", f"var SKIP = [\n    {sys_num}, // [AUTO]", 1)
            with open(poopsploit_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"\n\033[91m[AUTO-BLACKLIST]\033[0m Added sys({sys_num}) to SKIP list!\n")
        else:
            print(f"[!] AUTO-BLACKLIST skipped: marker 'var SKIP = [' not found in {poopsploit_path}")
    except Exception as e:
        print(f"[!] Failed to auto blacklist: {e}")



# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()
BLOCK_LOG_WINDOW_SECONDS = float(os.environ.get("BLOCK_LOG_WINDOW_SECONDS", "20"))
BLOCK_LOG_STATE = {}
PS5_LOG_WINDOW_SECONDS = float(os.environ.get("PS5_LOG_WINDOW_SECONDS", "2.5"))
PS5_LOG_STATE = {}
PS5_LOG_FILTER_ENABLED = os.environ.get("PS5_LOG_FILTER", "on").strip().lower() != "off"
PS5_SUMMARY_WINDOW_SECONDS = float(os.environ.get("PS5_SUMMARY_WINDOW_SECONDS", "0.5"))
PS5_SUMMARY_STATE = {}
LOADER_REINJECT_WINDOW_SECONDS = float(os.environ.get("LOADER_REINJECT_WINDOW_SECONDS", "30"))
LOADER_INJECT_MODE = os.environ.get("LOADER_INJECT_MODE", "session").strip().lower()
if LOADER_INJECT_MODE not in {"always", "session", "window"}:
    LOADER_INJECT_MODE = "session"
TJB_LOADER_PAYLOAD = os.environ.get("TJB_LOADER_PAYLOAD", "exploit").strip().lower()
if TJB_LOADER_PAYLOAD not in {"exploit", "webkit_probe"}:
    TJB_LOADER_PAYLOAD = "exploit"
APP_ATTACH_ACTIVE_WINDOW_SECONDS = float(os.environ.get("APP_ATTACH_ACTIVE_WINDOW_SECONDS", "45"))
LOADER_GRACE_WINDOW_SECONDS = float(os.environ.get("LOADER_GRACE_WINDOW_SECONDS", "18"))
LOADER_INJECT_STATE = {}
# Force Netflix blocking/corruption from code (no env override)
NETFLIX_CORRUPTION_MODE = "always"
PROXY_PUBLIC_IP_OVERRIDE = (
    os.environ.get("PROXY_PUBLIC_IP", "").strip()
    or os.environ.get("TJB_PROXY_PUBLIC_IP", "").strip()
)
CLIENT_PROXY_IP_STATE = {}
PROXY_IP_WARNED_CLIENTS = set()


def should_suppress_loader(state: Optional[dict], now: float) -> bool:
    if state is None:
        return False
    if LOADER_INJECT_MODE == "always":
        return False
    if LOADER_INJECT_MODE == "window":
        return (now - state["last_inject"]) < LOADER_REINJECT_WINDOW_SECONDS
    if LOADER_INJECT_MODE == "session":
        # Do not suppress pre-attach: keep serving loader until chain/log channel is alive.
        if not state.get("app_attached", False):
            return False
        last_seen = state.get("last_app_seen", 0.0)
        return state.get("app_attached", False) and (now - last_seen) < APP_ATTACH_ACTIVE_WINDOW_SECONDS
    return (now - state["last_inject"]) < LOADER_REINJECT_WINDOW_SECONDS


def get_loader_state(client_ip: str) -> dict:
    state = LOADER_INJECT_STATE.get(client_ip)
    if state is None:
        state = {
            "last_inject": 0.0,
            "suppressed_logged": False,
            "app_attached": False,
            "netflix_bypass_logged": False,
            "last_app_seen": 0.0,
            "loader_grace_until": 0.0,
        }
        LOADER_INJECT_STATE[client_ip] = state
    return state


def mark_app_attached(client_ip: str) -> None:
    state = get_loader_state(client_ip)
    state["app_attached"] = True
    state["last_app_seen"] = time.monotonic()


def should_bypass_netflix(client_ip: str) -> bool:
    if NETFLIX_CORRUPTION_MODE == "always":
        return False
    if NETFLIX_CORRUPTION_MODE == "never":
        return True

    state = LOADER_INJECT_STATE.get(client_ip)
    if not state:
        return False

    now = time.monotonic()
    if now < state.get("loader_grace_until", 0.0):
        return True
    if not state.get("app_attached"):
        return False
    if (now - state.get("last_app_seen", 0.0)) >= APP_ATTACH_ACTIVE_WINDOW_SECONDS:
        state["app_attached"] = False
        state["suppressed_logged"] = False
        state["netflix_bypass_logged"] = False
        return False
    return True


def _is_unusable_proxy_ip(ip: str) -> bool:
    return ip in {"", "0.0.0.0", "::", "127.0.0.1", "::1"}


def resolve_proxy_server_ip(flow: http.HTTPFlow, client_ip: str) -> str:
    if PROXY_PUBLIC_IP_OVERRIDE:
        return PROXY_PUBLIC_IP_OVERRIDE

    sockname = flow.client_conn.sockname
    candidate = sockname[0] if sockname else ""
    if candidate and not _is_unusable_proxy_ip(candidate):
        CLIENT_PROXY_IP_STATE[client_ip] = candidate
        return candidate

    remembered = CLIENT_PROXY_IP_STATE.get(client_ip)
    if remembered:
        return remembered

    if client_ip not in PROXY_IP_WARNED_CLIENTS:
        print(f"[!] WARN: unresolved proxy IP for {client_ip}, falling back to 127.0.0.1")
        PROXY_IP_WARNED_CLIENTS.add(client_ip)
    return "127.0.0.1"


def _fix_mojibake(text: str) -> str:
    """
    Attempt to recover UTF-8 text that arrived as latin-1 mojibake, e.g.:
    "â" -> "-"
    """
    if not text:
        return text
    if not any(ch in text for ch in ("Ã", "â", "Â")):
        return text
    try:
        fixed = text.encode("latin-1", errors="strict").decode("utf-8", errors="strict")
        return fixed if fixed else text
    except Exception:
        return text


def _ps5_log_channel(log_msg: str) -> Optional[str]:
    """
    Classify very noisy PS5 log lines so they can be rate-limited.
    """
    if "[NC] [noise]" in log_msg:
        return "nc-noise"
    if "[diag] heartbeat" in log_msg:
        return "diag-heartbeat"
    if "[NC] Det. round " in log_msg:
        return "nc-det-round"
    if "[0] sds progress:" in log_msg:
        return "stage0-progress"
    if "[diag] progress att=" in log_msg:
        return "stage1-progress"
    if re.search(r"\[1\] pipe_r=", log_msg):
        return "stage1-pipe"
    if re.search(r"\[1\] att=\d+ .*won=false", log_msg):
        return "stage1-attempt"
    if re.search(r"\[1\] att=\d+ .* M=", log_msg):
        return "stage1-detail"
    return None


def _ps5_log_summary(log_msg: str) -> Optional[tuple[str, str]]:
    """
    Emit a short milestone-oriented line for the exploit state machine.
    """
    if "=== STAGE 1" in log_msg:
        return ("stage1-enter", "[SUMMARY] Stage 1 entered")
    if "SUCCESS! ALIAS CAPTURED. EXITING RACE." in log_msg or "v1.2 done (won=true" in log_msg:
        return ("stage1-won", "[SUMMARY] Stage 1 won")
    if "=== STAGE 2: NETCONTROL PROBE" in log_msg:
        return ("stage2-enter", "[SUMMARY] Stage 2 entered")
    if "[!] ALIAS PAIR!" in log_msg:
        return ("twins-found", "[SUMMARY] Twin candidate found")
    if "ALIAS PAIR CAPTURED!" in log_msg:
        return ("twins-captured", "[SUMMARY] Twins captured")
    if "Starting Stage 3 (KASLR LEAK)..." in log_msg:
        return ("stage3-enter", "[SUMMARY] Stage 3 entered")
    if "KQUEUE RECLAIMED!" in log_msg:
        return ("kqueue-reclaimed", "[SUMMARY] Kqueue reclaimed")
    if "[***] KASLR LEAK:" in log_msg or "KASLR LEAK SUCCESS" in log_msg:
        return ("kaslr-leak", "[SUMMARY] KASLR leak obtained")
    if "FAILED: Twins elusive" in log_msg:
        return ("twins-failed", "[SUMMARY] Stage 2 failed: twins elusive")
    if "Stage 3 Failed: kqueue didn't land." in log_msg:
        return ("kqueue-failed", "[SUMMARY] Stage 3 failed: kqueue reclaim")
    return None


def _emit_ps5_summary(log_msg: str) -> None:
    summary = _ps5_log_summary(log_msg)
    if summary is None:
        return

    key, line = summary
    now = time.monotonic()
    state = PS5_SUMMARY_STATE.get(key)
    if state is not None and (now - state["last_log"]) < PS5_SUMMARY_WINDOW_SECONDS:
        return

    PS5_SUMMARY_STATE[key] = {"last_log": now}
    print(f"\033[96m{line}\033[0m")
    telemetry.emit_milestone(key, line)


def _emit_ps5_log(log_msg: str) -> None:
    """
    Print PS5 logs with optional rate-limiting for high-frequency noise.
    """
    _emit_ps5_summary(log_msg)

    if not PS5_LOG_FILTER_ENABLED:
        print(f"\033[92m[PS5]\033[0m {log_msg}")
        return

    channel = _ps5_log_channel(log_msg)
    if channel is None:
        print(f"\033[92m[PS5]\033[0m {log_msg}")
        return

    now = time.monotonic()
    state = PS5_LOG_STATE.get(channel)
    if state is None:
        PS5_LOG_STATE[channel] = {"last_log": now, "suppressed": 0}
        print(f"\033[92m[PS5]\033[0m {log_msg}")
        return

    elapsed = now - state["last_log"]
    if elapsed >= PS5_LOG_WINDOW_SECONDS:
        if state["suppressed"]:
            print(f"[*] Suppressed {state['suppressed']} repeated ps5 '{channel}' logs")
            state["suppressed"] = 0
        state["last_log"] = now
        print(f"\033[92m[PS5]\033[0m {log_msg}")
    else:
        state["suppressed"] += 1

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "hosts.txt")
    
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Extract domain (handle format: "0.0.0.0 domain.com" or just "domain.com")
                    parts = line.split()
                    domain = parts[-1] if parts else line
                    BLOCKED_DOMAINS.add(domain.lower())
        print(f"[+] Loaded {len(BLOCKED_DOMAINS)} blocked domains from hosts.txt")
    except FileNotFoundError:
        print(f"[!] WARNING: hosts.txt not found at {hosts_path}")
    except Exception as e:
        print(f"[!] ERROR loading hosts.txt: {e}")

# Load domains when script initializes
load_blocked_domains()
print(f"[+] Auto-blacklist mode: {AUTOBLACKLIST_MODE} (enabled={AUTOBLACKLIST_ENABLED})")
print(f"[+] Loader inject mode: {LOADER_INJECT_MODE} (window={LOADER_REINJECT_WINDOW_SECONDS}s, active_session={APP_ATTACH_ACTIVE_WINDOW_SECONDS}s, grace={LOADER_GRACE_WINDOW_SECONDS}s)")
print(f"[+] Loader payload: {TJB_LOADER_PAYLOAD}")
print(f"[+] Netflix corruption mode: {NETFLIX_CORRUPTION_MODE}")
print(f"[+] MITM telemetry: {telemetry.telemetry_status()}")
if PROXY_PUBLIC_IP_OVERRIDE:
    print(f"[+] Proxy public IP override: {PROXY_PUBLIC_IP_OVERRIDE}")
print("[i] Tip: use '--set termlog_verbosity=error' in mitmdump to hide noisy TLS handshake warnings.")

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def log_block_event(channel: str, hostname: str, message: str) -> None:
    """Rate-limit repetitive blocked-domain logs and emit suppression summaries."""
    key = (channel, hostname.lower())
    now = time.monotonic()
    state = BLOCK_LOG_STATE.get(key)

    if state is None:
        BLOCK_LOG_STATE[key] = {"last_log": now, "suppressed": 0}
        print(message)
        return

    elapsed = now - state["last_log"]
    if elapsed >= BLOCK_LOG_WINDOW_SECONDS:
        if state["suppressed"]:
            print(f"[*] Suppressed {state['suppressed']} repeated {channel} blocks for: {hostname}")
            state["suppressed"] = 0
        state["last_log"] = now
        print(message)
    else:
        state["suppressed"] += 1

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Don't raise here: mitmdump prints a full traceback for every blocked host.
        # We still block in request() for HTTP/CONNECT, and repeated pinned TLS attempts
        # will fail client-side without drowning the console.
        if is_blocked(hostname):
            telemetry.emit_block("tls", hostname, "TLS_CLIENTHELLO")
            log_block_event("tls", hostname, f"[*] Blocked TLS client hello for: {hostname}")


def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    global last_tried_sys, last_fuzz_info
    hostname = flow.request.pretty_host
    client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
    proxy_server_ip = resolve_proxy_server_ip(flow, client_ip)
    proxyServerIP = proxy_server_ip.encode("UTF-8")
    
    # === LOG ENDPOINT (must be first!) ===
    if flow.request.path.startswith("/log"):
        query = flow.request.query
        log_msg = _fix_mojibake(query.get("msg", ""))
        log_channel = _ps5_log_channel(log_msg)
        telemetry.emit_ps5_log(log_msg, client_ip, log_channel)
        if "[PT]" in log_msg:
            telemetry.emit_event("post_twin", client_ip=client_ip, message=log_msg)
        if "[WK]" in log_msg:
            telemetry.emit_event("webkit_probe", client_ip=client_ip, message=log_msg)
        _emit_ps5_log(log_msg)
        if log_msg.startswith("[TJB]"):
            mark_app_attached(client_ip)

        if AUTOBLACKLIST_ENABLED:
            with sys_lock:
                if "========================================" in log_msg:
                    if last_tried_sys is not None:
                        print(f"\033[91m[CRASH DETECTED]\033[0m Console restarted. sys({last_tried_sys}) caused a crash.")
                        auto_blacklist(last_tried_sys)
                        last_tried_sys = None
                elif "[FUZZ]" in log_msg:
                    last_fuzz_info = log_msg
                    match = re.search(r"sys\((\d+)\)", log_msg)
                    if match:
                        last_tried_sys = int(match.group(1))
                elif "[try] sys(" in log_msg:
                    match = re.search(r"\[try\] sys\((\d+)\)", log_msg)
                    if match:
                        last_tried_sys = int(match.group(1))
                elif "[HIT]" in log_msg or "[---]" in log_msg or "[RET]" in log_msg:
                    last_tried_sys = None

        flow.response = http.Response.make(200, b"OK", {
            "Content-Type": "text/plain",
            "Access-Control-Allow-Origin": "*"
        })
        return
    
    # Special handling for Netflix - corrupt the response
    if "netflix" in hostname:
        if should_bypass_netflix(client_ip):
            state = get_loader_state(client_ip)
            if not state.get("netflix_bypass_logged"):
                print(f"[*] Netflix corruption disabled for {client_ip} (app already attached)")
                state["netflix_bypass_logged"] = True
            return
        flow.response = http.Response.make( 
            200,
            b"uwu",  # probably don't need this many uwus. just corrupt the response 
            {"Content-Type": "application/x-msl+json"}
        )
        print(f"[*] Corrupted Netflix response for: {hostname}")
        return

    # Block other domains from hosts.txt
    if is_blocked(hostname):
        status_code = 444 if flow.request.method == "CONNECT" else 404
        body = b"" if status_code == 444 else b"uwu"
        flow.response = http.Response.make(status_code, body)
        telemetry.emit_block("http", hostname, flow.request.method, status_code)
        log_block_event(
            "http",
            hostname,
            f"[*] Blocked {flow.request.method} request to: {hostname}"
        )
        return

    # Map error text js to inject.js
    if "/js/common/config/text/config.text.lruderrorpage" in flow.request.path:
        state = get_loader_state(client_ip)
        now = time.monotonic()
        if should_suppress_loader(state, now):
            if not state.get("suppressed_logged"):
                if LOADER_INJECT_MODE == "session":
                    print(f"[*] Suppressing duplicate loader injection for {client_ip} (active session window)")
                else:
                    print(f"[*] Suppressing duplicate loader injection for {client_ip}")
                state["suppressed_logged"] = True
            flow.response = http.Response.make(
                200,
                b";/* duplicate loader request suppressed */",
                {"Content-Type": "application/javascript"}
            )
            telemetry.emit_route(
                "lruderrorpage-suppressed",
                flow.request.path,
                client_ip,
                200,
                "application/javascript",
                len(b";/* duplicate loader request suppressed */"),
                note="duplicate loader request suppressed",
            )
            return

        inject_name = "webkit_probe_harness.js" if TJB_LOADER_PAYLOAD == "webkit_probe" else "main.js"
        route_name = "lruderrorpage-webkit-probe" if TJB_LOADER_PAYLOAD == "webkit_probe" else "lruderrorpage-loader"
        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", inject_name)
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                payload_sha = hashlib.sha256(content).hexdigest()
                print(f"[+] Loaded {len(content)} bytes from {inject_name} sha256={payload_sha}")
                print(f"[SUMMARY] loader_payload {inject_name} sha256={payload_sha[:16]} bytes={len(content)}")
                state.update({
                    "last_inject": now,
                    "suppressed_logged": False,
                    "netflix_bypass_logged": False,
                    "last_app_seen": now,
                    "loader_grace_until": now + LOADER_GRACE_WINDOW_SECONDS,
                })
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route(
                    route_name,
                    flow.request.path,
                    client_ip,
                    200,
                    "application/javascript",
                    len(content),
                    inject_path,
                )
        except FileNotFoundError:
            print(f"[!] ERROR: {inject_name} not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                f"File not found: {inject_name}".encode("utf-8"),
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error(route_name, flow.request.path, client_ip, 404, f"{inject_name} not found")
        return

    
    if "/js/lapse.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "lapse.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from lapse.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("lapse", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
        except FileNotFoundError:
            print(f"[!] ERROR: lapse.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: lapse.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("lapse", flow.request.path, client_ip, 404, "lapse.js not found")
        return
            
    if "/js/elf_loader.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "elf_loader.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from elf_loader.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("elf_loader", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
        except FileNotFoundError:
            print(f"[!] ERROR: elf_loader.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elf_loader.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("elf_loader", flow.request.path, client_ip, 404, "elf_loader.js not found")
        return
    # Map poopsploit_chain.js
    if "/js/poopsploit_chain.js" in flow.request.path:
        mark_app_attached(client_ip)
        # In fuzz mode only: if payload is re-requested before status logs are emitted,
        # assume the last syscall crashed and auto-blacklist it.
        if AUTOBLACKLIST_ENABLED:
            with sys_lock:
                if last_tried_sys is not None:
                    print(f"\033[91m[CRASH DETECTED]\033[0m Console restarted. sys({last_tried_sys}) caused a crash.")
                    auto_blacklist(last_tried_sys)
                    last_tried_sys = None

        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "poopsploit_chain.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                chain_sha = hashlib.sha256(content).hexdigest()
                print(f"[+] INYECTADO: poopsploit_chain.js ({len(content)} bytes) sha256={chain_sha}")
                print(f"[SUMMARY] chain_sha poopsploit_chain.js sha256={chain_sha[:16]} bytes={len(content)}")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("poopsploit_chain", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
                return
        except FileNotFoundError:
            print(f"[!] ERROR: poopsploit_chain.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: poopsploit_chain.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("poopsploit_chain", flow.request.path, client_ip, 404, "poopsploit_chain.js not found")
            return

    # Map v8_escape_bridge.js — Native escape infrastructure
    if "/js/v8_escape_bridge.js" in flow.request.path:
        mark_app_attached(client_ip)
        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "v8_escape_bridge.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from v8_escape_bridge.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("v8_escape_bridge", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
                return
        except FileNotFoundError:
            print(f"[!] ERROR: v8_escape_bridge.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: v8_escape_bridge.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("v8_escape_bridge", flow.request.path, client_ip, 404, "v8_escape_bridge.js not found")
            return

    # Map kernel_exploit_stages.js — Stages 3-7 kernel exploit chain
    if "/js/kernel_exploit_stages.js" in flow.request.path:
        mark_app_attached(client_ip)
        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "kernel_exploit_stages.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from kernel_exploit_stages.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("kernel_exploit_stages", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
                return
        except FileNotFoundError:
            print(f"[!] ERROR: kernel_exploit_stages.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: kernel_exploit_stages.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("kernel_exploit_stages", flow.request.path, client_ip, 404, "kernel_exploit_stages.js not found")
            return

    # Map webkit_probe_harness.js for explicit/manual loading too.
    if "/js/webkit_probe_harness.js" in flow.request.path:
        mark_app_attached(client_ip)
        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "webkit_probe_harness.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxyServerIP)
                probe_sha = hashlib.sha256(content).hexdigest()
                print(f"[+] Loaded {len(content)} bytes from webkit_probe_harness.js sha256={probe_sha}")
                print(f"[SUMMARY] webkit_probe_sha webkit_probe_harness.js sha256={probe_sha[:16]} bytes={len(content)}")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("webkit_probe_harness", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
                return
        except FileNotFoundError:
            print(f"[!] ERROR: webkit_probe_harness.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: webkit_probe_harness.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("webkit_probe_harness", flow.request.path, client_ip, 404, "webkit_probe_harness.js not found")
            return

    # Map luacore_post_twin_equiv.js
    if "/js/luacore_post_twin_equiv.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "..", "exploit", "luacore_post_twin_equiv.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from luacore_post_twin_equiv.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("luacore_post_twin_equiv", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
        except FileNotFoundError:
            print(f"[!] ERROR: luacore_post_twin_equiv.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: luacore_post_twin_equiv.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("luacore_post_twin_equiv", flow.request.path, client_ip, 404, "luacore_post_twin_equiv.js not found")
        return


    # Map elfldr.elf to elfldr.elf (binary)
    if "/js/elfldr.elf" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "elfldr.elf")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from elfldr.elf")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("elfldr_elf", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
        except FileNotFoundError:
            print(f"[!] ERROR: elfldr.elf not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elfldr.elf",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("elfldr_elf", flow.request.path, client_ip, 404, "elfldr.elf not found")
        return
            
            
    if "/js/ps4/inject_auto_bundle.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "PS4", "inject_auto_bundle.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from inject_auto_bundle.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
                telemetry.emit_route("ps4_inject_auto_bundle", flow.request.path, client_ip, 200, "application/javascript", len(content), inject_path)
        except FileNotFoundError:
            print(f"[!] ERROR: inject_auto_bundle.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: inject_auto_bundle.js",
                {"Content-Type": "text/plain"}
            )
            telemetry.emit_route_error("ps4_inject_auto_bundle", flow.request.path, client_ip, 404, "inject_auto_bundle.js not found")
        return
