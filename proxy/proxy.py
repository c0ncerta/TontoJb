from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os
import threading
import re

# --- AUTO BLACKLIST STATE ---
last_tried_sys = None
last_fuzz_info = None  # Stores "sys(624) arg1=0x4141..." for Phase 2
sys_lock = threading.Lock()
poopsploit_path = os.path.join(os.path.dirname(__file__), "poopsploit_chain.js")
fuzz_log_path = os.path.join(os.path.dirname(__file__), "..", "DOCS", "fuzz_crashes.log")

# === FASE 3: Memory Pointer Fuzzing Targets (NO auto-blacklistear) ===
FUZZ_TARGETS = {649, 622, 522}

def auto_blacklist(sys_num):
    # FASE 2: Si esta syscall está bajo fuzzing activo, NO la bloqueamos
    if sys_num in FUZZ_TARGETS:
        msg = f"\n\033[93m[FUZZ-CRASH]\033[0m sys({sys_num}) crashed but is a FUZZ TARGET — NOT blacklisting!"
        if last_fuzz_info:
            msg += f"\n\033[93m[FUZZ-CRASH]\033[0m Args: {last_fuzz_info}"
        print(msg)
        # Log to file for analysis
        try:
            os.makedirs(os.path.dirname(fuzz_log_path), exist_ok=True)
            with open(fuzz_log_path, "a") as f:
                import datetime
                f.write(f"[{datetime.datetime.now()}] CRASH sys({sys_num}) | {last_fuzz_info or 'unknown args'}\n")
        except: pass
        return

    try:
        with open(poopsploit_path, "r") as f:
            content = f.read()
        
        # Check if already skipped
        if f"    {sys_num}," in content or f"    {sys_num} " in content:
            return
            
        # Insert at the beginning of the SKIP array to avoid comment/comma issues
        if "var SKIP = [" in content:
            new_content = content.replace("var SKIP = [", f"var SKIP = [\n    {sys_num}, // [AUTO]", 1)
            with open(poopsploit_path, "w") as f:
                f.write(new_content)
            print(f"\n\033[91m[AUTO-BLACKLIST]\033[0m Added sys({sys_num}) to SKIP list!\n")
    except Exception as e:
        print(f"[!] Failed to auto blacklist: {e}")
# ----------------------------

# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "hosts.txt")
    
    try:
        with open(hosts_path, "r") as f:
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

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Block domains at TLS layer
        if is_blocked(hostname):
            raise ConnectionRefusedError(f"[*] Blocked HTTPS connection to: {hostname}")


def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    hostname = flow.request.pretty_host
    proxyServerIP = flow.client_conn.sockname[0].encode("UTF-8")
    
    # === LOG ENDPOINT (must be first!) ===
    global last_tried_sys, last_fuzz_info
    import urllib.parse
    if flow.request.path.startswith("/log"):
        query = flow.request.query
        log_msg = query.get("msg", "")
        print(f"\033[92m[PS5]\033[0m {log_msg}")

        # Auto-Blacklist Logic
        with sys_lock:
            if "========================================" in log_msg:
                if last_tried_sys is not None:
                    print(f"\033[91m[CRASH DETECTED]\033[0m Console restarted. sys({last_tried_sys}) caused a crash.")
                    auto_blacklist(last_tried_sys)
                    last_tried_sys = None
            elif "[FUZZ]" in log_msg:
                # Phase 2: Capture fuzz argument info
                last_fuzz_info = log_msg
                m = re.search(r"sys\((\d+)\)", log_msg)
                if m:
                    last_tried_sys = int(m.group(1))
            elif "[try] sys(" in log_msg:
                m = re.search(r"\[try\] sys\((\d+)\)", log_msg)
                if m:
                    last_tried_sys = int(m.group(1))
            elif "[HIT]" in log_msg or "[---]" in log_msg or "[RET]" in log_msg:
                # Syscall survived

                last_tried_sys = None

        flow.response = http.Response.make(200, b"OK", {
            "Content-Type": "text/plain",
            "Access-Control-Allow-Origin": "*"
        })
        return
    
    # Special handling for Netflix - corrupt the response
    if "netflix" in hostname:
        flow.response = http.Response.make( 
            200,
            b"uwu",  # probably don't need this many uwus. just corrupt the response 
            {"Content-Type": "application/x-msl+json"}
        )
        print(f"[*] Corrupted Netflix response for: {hostname}")
        return

    # Block other domains from hosts.txt
    if is_blocked(hostname):
        flow.response = http.Response.make( 
            404,
            b"uwu",
        )
        print(f"[*] Blocked HTTP request to: {hostname}")
        return

    # Map error text js to inject.js
    if "/js/common/config/text/config.text.lruderrorpage" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "inject_elfldr_automated.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] Loaded {len(content)} bytes from inject.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: inject.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: inject.js",
                {"Content-Type": "text/plain"}
            )

    
    if "/js/lapse.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "lapse.js")
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
        except FileNotFoundError:
            print(f"[!] ERROR: lapse.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: 1_lapse_prepare_1.js",
                {"Content-Type": "text/plain"}
            )
            
    if "/js/elf_loader.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "elf_loader.js")
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
        except FileNotFoundError:
            print(f"[!] ERROR: lapse.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elf_loader.js",
                {"Content-Type": "text/plain"}
            )
    # Map poopsploit_chain.js
    if "/js/poopsploit_chain.js" in flow.request.path:
        # Pre-emptive Crash Detection (Fix Race Condition)
        # If the console is requesting the JS payload but never finished the last syscall, it crashed!
        # Do this BEFORE reading the file so the new payload includes the blacklist update.
        with sys_lock:
            if last_tried_sys is not None:
                print(f"\033[91m[CRASH DETECTED]\033[0m Console restarted. sys({last_tried_sys}) caused a crash.")
                auto_blacklist(last_tried_sys)
                last_tried_sys = None
                
        inject_path = os.path.join(os.path.dirname(__file__), "poopsploit_chain.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS",proxyServerIP)
                print(f"[+] INYECTADO: poopsploit_chain.js ({len(content)} bytes)")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: poopsploit_chain.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: poopsploit_chain.js",
                {"Content-Type": "text/plain"}
            )


    # Map elfldr.elf to elfldr.elf (binary)
    if "/js/elfldr.elf" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "elfldr.elf")
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
        except FileNotFoundError:
            print(f"[!] ERROR: elfldr.elf not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elfldr.elf",
                {"Content-Type": "text/plain"}
            )
            
            
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
        except FileNotFoundError:
            print(f"[!] ERROR: inject_auto_bundle.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: inject_auto_bundle.js",
                {"Content-Type": "text/plain"}
            )
