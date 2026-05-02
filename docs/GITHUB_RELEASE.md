# GitHub release checklist

Use this checklist before making the repository public.

## Required checks

- [ ] Review `git status --short` and stage only intentional source/docs files.
- [ ] Confirm `.mitmproxy_certs/` is ignored and never staged.
- [ ] Confirm `LOGS/` and `*.jsonl` telemetry captures are ignored.
- [ ] Confirm `.DS_Store`, `__pycache__/`, and local caches are ignored.
- [ ] Confirm `docs/logito/` and proxy dump files are not staged.
- [ ] Confirm `exploit/`, `payloads/`, and `offsets/` changes are intentional.
- [ ] Search staged files for local absolute paths before committing.
- [ ] Search staged files for private keys, tokens, passwords, and secrets.
- [ ] Run README syntax-check commands from repository root.
- [ ] Read the top-level README from a new visitor's perspective.

## Suggested staging strategy

1. Stage hygiene/docs first:

   ```bash
   git add .gitignore README.md docs/README.md docs/GITHUB_RELEASE.md docs/mitm_mcp_telemetry.md
   ```

2. Review the staged diff:

   ```bash
   git diff --cached
   ```

3. Stage exploit/payload changes only after a separate intentional review:

   ```bash
   git status --short exploit payloads offsets proxy tools
   ```

4. Create a release commit once the staged diff contains only public-ready material.

## Do not publish

- mitmproxy CA files or generated certificates.
- Raw telemetry logs containing private LAN addresses.
- Console dumps pasted as documentation.
- Local agent memory, editor state, or scratch planning folders.
- Any file whose provenance or publication intent is unclear.
