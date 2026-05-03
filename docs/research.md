# TontoJB — Research Log

## Project Origin

This project started as an exploration of the Netflix app sandbox on PS5 11.60 Digital Edition. The goal was to determine if kernel-level code execution could be achieved through the Netflix WebKit process without requiring a disc-based exploit (mast1c0re).

The research was conducted as part of `poopsploit-net-n`, building on existing work from Luac0re, Y2JB, and kstuff-lite.

## Phase 1: Sandbox Capabilities Discovery

### Initial Findings
- The Netflix app on PS5 runs inside a WebKit-based process with `main.js` providing memory R/W primitives (`malloc`, `read64_uncompressed`, `write64_uncompressed`) and raw `syscall()` access.
- The app communicates via HTTP to `nrdp60-appboot.netflix.com`, which can be intercepted by a MITM proxy to inject arbitrary JavaScript.

### Socket Tests
| Socket Type | Result |
|------------|--------|
| `AF_INET6, SOCK_DGRAM, 0` | ✅ Works |
| `AF_INET6, SOCK_DGRAM, IPPROTO_IPV6(41)` | ❌ Blocked |
| `AF_INET6, SOCK_STREAM, 0` | ✅ Works |
| `AF_UNIX, SOCK_STREAM, 0` | ✅ Works (surprise!) |

> **Key finding**: `socket(AF_UNIX)` is NOT blocked in the Netflix sandbox, despite PS5 FW ≥ 8.00 blocking it for regular apps. This is likely because Netflix uses a different sandbox profile.

### setsockopt/getsockopt Tests
| Option | setsockopt | getsockopt | Bytes |
|--------|-----------|------------|-------|
| `IPV6_2292PKTOPTIONS` | ✅ ret=0 | ✅ ret=0, bytes=0 | 0 |
| `IPV6_PKTINFO` | ✅ | ✅ | 20 |
| `IPV6_RTHDR` (direct) | ✅ ret=0 | ✅ | 256 |
| `IPV6_TCLASS` | ✅ | ✅ | 4 |
| `TCP_INFO` | ✅ | ✅ | 136 |

## Phase 2: UAF Technique Evaluation

### Simple ip6_pktopts UAF — PATCHED
Tested 3 techniques:
1. **Double-set**: `setsockopt(2292)` twice → No corruption detected
2. **Clear-options**: Set then clear with `len=0` → No dangling pointer
3. **Bulk + individual overlap**: 2292 bulk + TCLASS individual → Only reset, no UAF

**Conclusion**: Sony patched the simple ip6_pktopts UAF paths on 11.60.

### Reference Code Analysis
Analyzed 3 implementations:
- **lapse.js** (Y2JB): AIO double-free → pktopts aliasing → PKTINFO master/victim R/W
- **poops_ps5.lua** (Luac0re): `sys_netcontrol` UAF → rthdr twin/triplet → pipe corruption → kread/kwrite
- **r0gdb.c** (kstuff-lite): Post-exploit primitives using IPV6_PKTINFO master/victim pattern

## Phase 3: Luac0re Requirements Verification

Comprehensive test of all 15 syscalls required by `poops_ps5.lua`:

| # | Syscall | Result |
|---|---------|--------|
| 1 | `socket(AF_UNIX)` | ✅ fd=23 |
| 2 | `socketpair(AF_UNIX)` | ✅ fds=23,31 |
| 3 | `socket(AF_INET6, SOCK_STREAM)` | ✅ fd=23 |
| 4 | `setsockopt(IPV6_RTHDR)` | ✅ 360 bytes |
| 5 | `getsockopt(IPV6_RTHDR)` | ✅ 256 bytes, tags correct |
| 6 | `free_rthdr(RTHDR, 0, 0)` | ✅ ret=0 |
| 7 | `pipe()` | ✅ fd in retval |
| 8 | `kqueue()` | ✅ fd=33 |
| 9 | `dup()` | ❌ Blocked |
| 10 | `setuid(1)` | ✅ ret=0 |
| 11 | `netcontrol(-1, 0x20000003)` | ✅ ret=0 |
| 12 | `fcntl(F_SETFL)` | ❌ Blocked |
| 13 | `ioctl(FIOSETOWN)` | ⚠️ Needs retest |
| 14 | `sched_yield()` | ✅ ret=0 |
| 15 | **64 socket spray + rthdr** | ✅ 64/64 OK, all tags correct |

### Critical Discovery
The rthdr spray with 64 IPv6 STREAM sockets works **perfectly**:
```
s0=0x13370000(256b), s1=0x13370001(256b), ..., s9=0x13370009(256b)
```
Every tag was read back correctly, confirming the spray mechanism is viable.

## Phase 4: Exploit Implementation (In Progress)

### Stage 0: Triple-Free Race
- Implementation ported from Luac0re `poops_ps5.lua`
- Completely single-threaded
- Uses: `socket(AF_UNIX)` → `netcontrol(-1, 0x20000003)` → `close` → `setuid(1)` → rthdr spray → `find_twins()`

### Known Blockers
1. **Threading**: Luac0re uses 8 ROP worker threads for kread_slow/kwrite_slow race condition. Netflix sandbox is single-threaded JS. Alternative approaches being explored.
2. **dup()**: Blocked, but only used for cleanup (non-critical).
3. **fcntl()**: Blocked, workaround via `setsockopt(SO_RCVTIMEO)`.
