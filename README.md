# TontoJB

PS5 Kernel Exploit via Netflix Sandbox — FW 11.60

## Overview

TontoJB is a PS5 jailbreak that achieves kernel-level code execution through the Netflix app's WebKit sandbox. It exploits a UCred Use-After-Free (UAF) vulnerability triggered via `sys_netcontrol`, combined with IPv6 `ip6_pktopts` heap grooming to establish kernel read/write primitives.

**No disc required. No USB. Just Netflix and a proxy.**

## How It Works

```
Netflix App (WebKit) → MITM Proxy → JS Injection → syscall primitives
    → sys_netcontrol UAF → rthdr heap spray → kqueue reclaim
    → kernel R/W → ucred patch → root + sandbox escape
```

### Exploit Chain

| Stage | Name | Description |
|-------|------|-------------|
| 0 | Triple-Free Race | Trigger UCred UAF via `sys_netcontrol`, spray IPv6 rthdr buffers, find overlapping sockets (twins/triplets) |
| 1 | Kqueue Reclaim | Free a triplet's rthdr, reclaim with `kqueue()`, leak `proc_filedesc` from kernel |
| 2 | Pipe Leak | Read kernel pipe data pointers via overlapping rthdr |
| 3 | Pipe Corruption | Corrupt pipe buffer for fast arbitrary kernel R/W |
| 4 | Find curproc | Walk kernel structures to find current process |
| 5 | Jailbreak | Patch `ucred` (uid=0, caps=0xFF...FF), escape AppJail sandbox |

## Requirements

- PS5 console on firmware **11.60** (or compatible, see offsets)
- Netflix app installed
- Computer on the same network running the MITM proxy
- Python 3 with `mitmproxy` installed

## Usage

### 1. Setup Proxy
```bash
cd proxy/
pip install mitmproxy
```

### 2. Configure PS5 Network
Set your PS5's proxy to point to your computer's IP on port 8080.

### 3. Run
```bash
mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 8080 --ssl-insecure --set connection_strategy=lazy
```

### 4. Launch Netflix
Open Netflix on your PS5. The exploit runs automatically.

## Project Structure

```
TontoJB/
├── exploit/
│   ├── poopsploit_chain.js    # Main exploit payload (Stage 0-5)
│   └── inject_elfldr.js       # WebKit injection + syscall primitives
├── proxy/
│   ├── proxy.py               # MITM proxy with JS injection
│   └── hosts.txt              # Blocked telemetry domains
├── offsets/
│   └── offsets.js              # Kernel struct offsets per FW version
├── payloads/
│   └── lapse.js               # Post-exploitation payload
├── docs/
│   ├── research.md            # Full research log
│   └── syscall_results.md     # Verified syscall availability
└── README.md
```

## Verified Syscalls (Netflix Sandbox)

| Syscall | Status | Notes |
|---------|--------|-------|
| `socket(AF_UNIX)` | ✅ | Not blocked in Netflix sandbox |
| `socket(AF_INET6, SOCK_STREAM)` | ✅ | TCP sockets work |
| `socketpair(AF_UNIX)` | ✅ | |
| `setsockopt(IPV6_RTHDR)` | ✅ | Set + read + free all work |
| `getsockopt(IPV6_RTHDR)` | ✅ | Returns 256 bytes with correct tags |
| `sys_netcontrol` | ✅ | UAF trigger confirmed |
| `setuid(1)` | ✅ | |
| `kqueue()` | ✅ | Stage 1 reclaim |
| `pipe()` | ✅ | fd in return value |
| `sched_yield()` | ✅ | |
| `setsockopt(IPV6_PKTINFO)` | ✅ | 20 bytes R/W |
| `setsockopt(IPV6_TCLASS)` | ✅ | |
| `mmap(ANON, RW)` | ✅ | |
| `dup()` | ❌ | Blocked |
| `fcntl()` | ❌ | Blocked |
| `umtx_op` | ❌ | Hangs process |

## Kernel Offsets (FW 11.60)

```javascript
// From Luac0re offsets.lua — FW 11.60 = 11.00
DATA_BASE         = 0x0D30000
ALLPROC           = 0x02875D70
SECURITY_FLAGS    = 0x00D8C064
ROOTVNODE         = 0x030B7510
KERNEL_PMAP_STORE = 0x02E04F18

PROC_PID          = 0xBC
PROC_UCRED        = 0x40
PROC_FD           = 0x48
INPCB_PKTOPTS     = 0x120
IP6PO_RTHDR       = 0x70
PIPE_SIGIO        = 0xD8
```

## Credits & Attribution

This project builds on the work of many talented researchers:

- **[TheFlow](https://github.com/theofficialflow)** — Original `sys_netcontrol` kernel exploit
- **[egycnq](https://github.com/egycnq)** — Porting netcontrol exploit to Luac0re (`poops_ps5.lua`)
- **[Gezine/Luac0re](https://github.com/Gezine/Luac0re)** — Lua-based PS5 exploit framework, kernel offsets
- **[sleirsgoevy](https://github.com/sleirsgoevy)** — `kstuff-lite` / `prosper0gdb` kernel primitives (kread/kwrite via IPV6_PKTINFO)
- **[Y2JB / lapse.js](https://github.com/)** — AIO-based UAF technique, `make_aliased_pktopts`, kernel ARW via PKTINFO master/victim pattern
- **[CTurt](https://github.com/CTurt)** — `mast1c0re` writeup
- **[McCaulay](https://github.com/McCaulay)** — `mast1c0re` reference implementation
- **Netflix WebKit exploit chain** — `inject_elfldr_automated.js` primitives (malloc, read64/write64, syscall wrappers)

## Disclaimer

This tool is provided for **educational and research purposes only**.
Use at your own risk. The developers are not responsible for any damage, data loss, or other consequences resulting from the use of this software.

## License

MIT
