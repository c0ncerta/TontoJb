# TontoJB

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Research PoC](https://img.shields.io/badge/status-research%20PoC-orange.svg)](docs/policy/DISCLAIMER.md)
[![Target: PS5 9.00–12.00](https://img.shields.io/badge/target-PS5%209.00–12.00-blue.svg)](docs/firmware-scope.md)

**PS5 Netflix-sandbox kernel exploit proof of concept for firmware 9.00–12.00.**

TontoJB documents and implements a research PoC for driving the PS5 Netflix WebKit process into a kernel-exploitation chain: MITM-assisted JavaScript injection, syscall primitive validation, AIO double-free race triggering, IPv6 `ip6_pktopts` heap shaping, kernel read/write primitives, and sandbox/credential patching research.

This repository is written for security researchers, console-research developers, and people already comfortable with kernel exploitation concepts. It is a research-only proof of concept, not a consumer jailbreak package, piracy tool, or supported end-user product.

Read first: [`DISCLAIMER.md`](docs/policy/DISCLAIMER.md), [`SECURITY.md`](docs/policy/SECURITY.md), [`NOTICE.md`](docs/policy/NOTICE.md), and [`docs/firmware-scope.md`](docs/firmware-scope.md).

## Responsible-use notice

- Use this only on hardware you own and accept full responsibility for.
- This can crash, soft-brick, or otherwise destabilize a console.
- Do not use this for piracy, unauthorized access, commercial abuse, or activity that violates applicable law or terms of service.
- Firmware updates may patch relevant bugs; unsupported firmware should be expected to fail.
- The project is provided as-is for research and education, without warranty.

## Research status

| Area | Status | Notes |
|---|---:|---|
| Target firmware | 9.00–12.00 | Offsets cover 9.00, 10.x, 11.x, and 12.00. 11.20/11.40/11.60 share 11.00 offsets. |
| Delivery path | Netflix + MITM proxy | No disc path is required for this research route. |
| Sandbox syscalls | Verified subset | See syscall table and `docs/research.md`. |
| AIO double-free race | Active exploit path | `poopsploit_chain.js` — same-core suspend/resume race. |
| Kernel R/W chain | Research PoC | Reliability depends on runtime state and target conditions. |

## Exploit chain

```text
Netflix app WebKit
  -> local mitmproxy route replacement
  -> JavaScript loader / syscall primitives
  -> AIO double-free race (poopsploit_chain.js)
  -> IPv6 rthdr heap spray and twin discovery
  -> ucred overlap and privilege escalation
  -> pipe corruption kernel R/W primitives
  -> curproc discovery and sandbox escape
  -> debug flag patches (security_flags, target_id, qa_flags, utoken)
  -> auth/caps escalation (SYSTEM_AUTHID, sceCaps max)
  -> ELF loader (elfldr.elf, port 9021)
```

### Stage overview

| Stage | Name | Purpose |
|---:|---|---|
| 1 | AIO double-free race | Race `aio_multi_delete` on same core to double-free AIO request. |
| 2 | Twin discovery | IPv6 rthdr spray, ucred overlap, privilege escalation, dup unlock. |
| 3 | KASLR leak | Kqueue reclaim to leak kernel base address. |
| 4 | Pipe corruption | Corrupt pipe buffer pointer for fast arbitrary kernel R/W. |
| 5 | Jailbreak | `curproc` walk, uid=0, rootvnode patch, sandbox escape. |
| 6 | Debug patches | `security_flags`, `target_id` (DEX), `qa_flags`, `utoken_flags`. |
| 7 | Auth/caps | `SYSTEM_AUTHID` + `sceCaps[0/1] = 0xFFFF…`, ELF loader launch. |

## Requirements

- PS5 on firmware **9.00–12.00** (11.20, 11.40, 11.60 use 11.00 offsets).
- Netflix app installed and launchable.
- A computer on the same network as the console.
- Python 3 and `mitmproxy` for the local proxy path.
- Node.js for JavaScript syntax checks.

## Quick start

From a clean checkout:

```bash
python3 -m pip install mitmproxy
```

Run quick syntax checks before launching the proxy:

```bash
node --check exploit/poopsploit_chain.js
node --check exploit/main.js
python3 -m py_compile proxy/proxy.py
```

Optional local network config: keep private IPs out of commits by copying
[`proxy/local.env.example`](proxy/local.env.example) to `proxy/local.env` and setting
`TJB_PROXY_PUBLIC_IP` there. `proxy/local.env`, `.env.local`, and other local config
overrides are ignored by git; the public code keeps generic placeholders.

Start the proxy from the repository root:

```bash
mitmdump \
  -s proxy/proxy.py \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --ssl-insecure \
  --set connection_strategy=lazy
```

Configure the PS5 network proxy to point at the computer running `mitmdump` on port `8080`, then launch Netflix. The proxy replaces selected Netflix JavaScript responses with the local loader chain.

## Runtime modes

- `TJB_RUNTIME.exploit_mode` is set to `netcontrol` in `exploit/main.js` but the active exploit path is `poopsploit_chain.js` (AIO double-free).
- `TJB_FW_VERSION` is detected at runtime; offsets cover 9.00–12.00.
- `proxy/proxy.py` keeps auto-blacklist behavior disabled by default: `AUTOBLACKLIST_MODE=off`.
- Fuzz auto-blacklist mode can be enabled explicitly when doing controlled crash triage:

```bash
AUTOBLACKLIST_MODE=fuzz mitmdump \
  -s proxy/proxy.py \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --ssl-insecure \
  --set connection_strategy=lazy
```

## Success indicators

For a successful run, the console/proxy logs should include milestones similar to:

- `[TJB] Stage 1 winner found` — AIO double-free race won
- `[TJB] TWINS_FOUND` — overlapping ucred sockets found
- `[TJB] privilege_escalated=true dup=true` — Stage 2 complete
- `[KS] Gezine path: privilege=true dup=true` — kernel stages started
- `TontoJB: Kernel jailbreak complete!` — Stage 7 done, ELF loader launching

Useful failure signatures include repeated Stage 1 races without a winner, Stage 2 ending without twins, or route errors showing a local payload file was not served.

## Verified Netflix-sandbox syscalls

| Syscall / primitive | Status | Notes |
|---|---:|---|
| `socket(AF_UNIX)` | ✅ | Available inside the tested Netflix sandbox. |
| `socket(AF_INET6, SOCK_STREAM)` | ✅ | IPv6 TCP sockets work. |
| `socketpair(AF_UNIX)` | ✅ | Available during syscall probing. |
| `setsockopt(IPV6_RTHDR)` | ✅ | Set, read, and free paths validated. |
| `getsockopt(IPV6_RTHDR)` | ✅ | Returns expected tagged data. |
| `sys_netcontrol` | ✅ | Available; UAF path researched but active chain uses AIO double-free. |
| `setuid(1)` | ✅ | Used in the race sequence. |
| `kqueue()` | ✅ | Used for Stage 1 reclaim. |
| `pipe()` | ✅ | Available for pipe primitive work. |
| `sched_yield()` | ✅ | Available. |
| `setsockopt(IPV6_PKTINFO)` | ✅ | Useful for pktopts-backed R/W patterns. |
| `setsockopt(IPV6_TCLASS)` | ✅ | Available. |
| `mmap(ANON, RW)` | ✅ | Available. |
| `dup()` | ✅ | Unlocked after ucred privilege escalation in Stage 2. |
| `fcntl()` | ✅ | Used for non-blocking pipe setup in Stage 3. |
| `umtx_op` | ✅ | Used as ROP worker synchronization mechanism in Stage 3+. |

## Repository layout

```text
TontoJB/
├── exploit/        # Exploit chain, loader, and research-stage JS components
├── payloads/       # Post-exploitation payload experiments and loader assets
├── proxy/          # mitmproxy delivery layer and host blocking configuration
├── offsets/        # Firmware-specific kernel offsets
├── docs/           # Research notes, policy docs, telemetry docs, and run matrices
├── tools/          # Local analysis and telemetry helper scripts
├── LICENSE         # MIT license
└── README.md       # Public entry point
```

The repository intentionally ignores local certificates, runtime telemetry, cache folders, and console-log dumps. See `.gitignore` before staging a public release.

## Documentation

- [`docs/README.md`](docs/README.md) — documentation map and publication notes.
- [`docs/architecture.md`](docs/architecture.md) — high-level architecture and trust-boundary overview.
- [`docs/firmware-scope.md`](docs/firmware-scope.md) — supported target assumptions and unsupported firmware notes.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — setup-level troubleshooting and publication hygiene checks.
- [`docs/research.md`](docs/research.md) — research log and syscall capability findings.
- [`docs/mitm_mcp_telemetry.md`](docs/mitm_mcp_telemetry.md) — local telemetry/MCP workflow.
- [`docs/run-matrix.md`](docs/run-matrix.md) — run comparison notes, if included in your release.
- [`docs/post_twin_pipeline.md`](docs/post_twin_pipeline.md) — post-twin execution notes, if included in your release.

## Project policy files

- [`docs/policy/DISCLAIMER.md`](docs/policy/DISCLAIMER.md) — public research-use boundaries and risk acknowledgement.
- [`docs/policy/SECURITY.md`](docs/policy/SECURITY.md) — responsible reporting scope and out-of-scope support requests.
- [`docs/policy/NOTICE.md`](docs/policy/NOTICE.md) — third-party attribution and provenance guidance.
- [`docs/policy/CONTRIBUTING.md`](docs/policy/CONTRIBUTING.md) — contribution boundaries for safe public research work.
- [`docs/policy/CHANGELOG.md`](docs/policy/CHANGELOG.md) — public research snapshot history.

## Known limitations

- Tested firmware range is 9.00–12.00; behavior on other versions is untested.
- Netflix JavaScript execution is constrained compared with native or multi-threaded environments.
- Some syscalls used in related chains are blocked or unreliable in this sandbox.
- Reliability depends on heap state, timing, route delivery, and target runtime behavior.
- Local telemetry may include private network addresses; keep runtime logs out of public commits.

## Credits and attribution

TontoJB is a port/adaptation and integration effort that stands on public PS5 and FreeBSD exploitation research. The implementation, Netflix delivery path, and repository-specific research notes here should be credited to this repository's author/contributors; the underlying vulnerability classes, primitives, and techniques remain credited to their original researchers.

Prior work and references include:

- [Netflix-N-Hack](https://github.com/NetflixNHack/Netflix-N-Hack) — foundational Netflix delivery, injection, and payload-loading work that TontoJB builds on and significantly adapts.
- [TheFlow](https://github.com/theofficialflow) — original `sys_netcontrol` kernel exploitation research.
- [egycnq](https://github.com/egycnq) — Luac0re-oriented netcontrol work and `poops_ps5.lua` lineage.
- [Gezine / Luac0re](https://github.com/Gezine/Luac0re) — Lua-based PS5 exploit framework and offsets lineage.
- [sleirsgoevy](https://github.com/sleirsgoevy) — `kstuff-lite`, `prosper0gdb`, and kernel primitive references.
- [Gezine / Y2JB](https://github.com/Gezine/Y2JB) / `lapse.js` lineage — AIO and `ip6_pktopts`-style exploitation references.
- [CTurt](https://github.com/CTurt) and [McCaulay](https://github.com/McCaulay) — `mast1c0re` research and references.

If you publish derivative work from this repository, keep these credits intact and clearly distinguish original discovery from porting, adaptation, and integration work.

## Contributing boundaries

- Keep exploit-chain changes narrowly scoped and documented.
- Do not commit private certificates, runtime telemetry, crash dumps, or local network logs.
- Prefer reproducible notes in `docs/` over raw console dumps.
- Document firmware assumptions when adding offsets or changing target behavior.

## License

This repository is released under the MIT License. See [`LICENSE`](LICENSE).
