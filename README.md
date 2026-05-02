# TontoJB

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Research PoC](https://img.shields.io/badge/status-research%20PoC-orange.svg)](docs/policy/DISCLAIMER.md)
[![Target: PS5 11.60](https://img.shields.io/badge/target-PS5%2011.60-blue.svg)](docs/firmware-scope.md)

**PS5 Netflix-sandbox kernel exploit proof of concept for firmware 11.60.**

TontoJB documents and implements a research PoC for driving the PS5 Netflix WebKit process into a kernel-exploitation chain: MITM-assisted JavaScript injection, syscall primitive validation, `sys_netcontrol` UCred UAF triggering, IPv6 `ip6_pktopts` heap shaping, kernel read/write primitives, and sandbox/credential patching research.

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
| Target firmware | 11.60 | Offsets are pinned to the documented 11.60 research target. |
| Delivery path | Netflix + MITM proxy | No disc path is required for this research route. |
| Sandbox syscalls | Verified subset | See syscall table and `docs/research.md`. |
| Netcontrol UAF path | Implemented PoC | Based on public prior work, adapted for this environment. |
| Kernel R/W chain | Research PoC | Reliability depends on runtime state and target conditions. |

## Exploit chain

```text
Netflix app WebKit
  -> local mitmproxy route replacement
  -> JavaScript loader / syscall primitives
  -> sys_netcontrol UCred UAF trigger
  -> IPv6 rthdr heap spray and twin/triplet discovery
  -> kqueue reclaim and kernel structure leaks
  -> pipe / pktopts kernel R/W primitives
  -> curproc discovery
  -> ucred patch and sandbox escape research
```

### Stage overview

| Stage | Name | Purpose |
|---:|---|---|
| 0 | Triple-free race | Trigger UCred UAF and search overlapping sockets. |
| 1 | Kqueue reclaim | Reclaim freed rthdr memory and leak `proc_filedesc`. |
| 2 | Pipe leak | Recover kernel pipe data pointers through overlap. |
| 3 | Pipe corruption | Establish faster arbitrary kernel read/write. |
| 4 | `curproc` discovery | Walk kernel structures for the current process. |
| 5 | Jailbreak research | Patch credential and sandbox-related process state. |

## Requirements

- PS5 on firmware **11.60** or a deliberately compatible research target.
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
node --check exploit/inject_elfldr_automated.js
python3 -m py_compile proxy/proxy.py
```

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

- `TJB_RUNTIME.exploit_mode` defaults to the `netcontrol` path in `exploit/inject_elfldr_automated.js`.
- `TJB_RUNTIME.fw_target` is pinned to `11.60` for the current research stage.
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

For a successful netcontrol path up to the KASLR-leak phase, the console/proxy logs should include milestones similar to:

- `[S0] TWINS_FOUND ...`
- `[S0] TRIPLETS_FOUND ...`
- `[S1] KQUEUE_RECLAIM_OK ...`
- `[S1] PROC_FILEDESC=0x...`

Useful failure signatures include repeated Stage 0 progress without twins, Stage 1 attempts ending without kqueue reclaim, or route errors showing that a local payload file was not served.

## Verified Netflix-sandbox syscalls

| Syscall / primitive | Status | Notes |
|---|---:|---|
| `socket(AF_UNIX)` | ✅ | Available inside the tested Netflix sandbox. |
| `socket(AF_INET6, SOCK_STREAM)` | ✅ | IPv6 TCP sockets work. |
| `socketpair(AF_UNIX)` | ✅ | Available during syscall probing. |
| `setsockopt(IPV6_RTHDR)` | ✅ | Set, read, and free paths validated. |
| `getsockopt(IPV6_RTHDR)` | ✅ | Returns expected tagged data. |
| `sys_netcontrol` | ✅ | UAF trigger path confirmed for research. |
| `setuid(1)` | ✅ | Used in the race sequence. |
| `kqueue()` | ✅ | Used for Stage 1 reclaim. |
| `pipe()` | ✅ | Available for pipe primitive work. |
| `sched_yield()` | ✅ | Available. |
| `setsockopt(IPV6_PKTINFO)` | ✅ | Useful for pktopts-backed R/W patterns. |
| `setsockopt(IPV6_TCLASS)` | ✅ | Available. |
| `mmap(ANON, RW)` | ✅ | Available. |
| `dup()` | ❌ | Blocked in this sandbox. |
| `fcntl()` | ❌ | Blocked in this sandbox. |
| `umtx_op` | ❌ | Observed to hang the process. |

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

- The current target scope is intentionally narrow: firmware 11.60 research conditions.
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
