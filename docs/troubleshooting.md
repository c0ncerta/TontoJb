# Troubleshooting

This page covers public, setup-level troubleshooting for the TontoJB research repository. It deliberately avoids exploit reliability tuning, payload weaponization, or firmware-shopping guidance.

## Before troubleshooting

- Confirm you are working from a clean checkout.
- Confirm your use is authorized and consistent with [`../DISCLAIMER.md`](../DISCLAIMER.md).
- Confirm local certificates, logs, telemetry, and crash dumps are not staged for publication.
- Confirm the target assumptions match [`firmware-scope.md`](firmware-scope.md).

## Common setup issues

| Symptom | Check | Notes |
|---|---|---|
| Python proxy script will not start | Confirm Python 3 and mitmproxy are installed | Use a local virtual environment if your system Python is managed. |
| JavaScript syntax check fails | Run the documented `node --check` command on the changed file | Fix syntax before attempting runtime research. |
| Proxy route does not serve a local file | Confirm the path exists in the repository checkout | Avoid absolute local paths in committed documentation. |
| Browser or app trust errors appear | Confirm local mitmproxy certificate setup | Do not commit certificate material or private CA files. |
| Logs contain private network details | Redact before writing public notes | Prefer summarized observations over raw logs. |

## Publication hygiene checks

Before opening a pull request or publishing a snapshot:

```bash
git status --short
git check-ignore -v docs/otros/example.md gezine/example.txt
```

Expected behavior: local-only folders such as `docs/otros/` and `gezine/` remain ignored. If they do not, review `.gitignore` before staging.

## What this page does not provide

- No exploit-success tuning.
- No instructions for unsupported firmware.
- No piracy, cheating, DRM bypass, or unauthorized-access support.
- No guidance for attacking third-party services, accounts, networks, or devices.

For research context, start with [`research.md`](research.md), [`architecture.md`](architecture.md), and [`firmware-scope.md`](firmware-scope.md).
