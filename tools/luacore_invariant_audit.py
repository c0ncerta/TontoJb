#!/usr/bin/env python3
"""Offline Luac0re-style invariant audit for TontoJB run logs.

This tool does not run or modify exploit code. It reads captured logs from
``TontoJB/logos`` and classifies each run against the high-level invariants
that Luac0re relies on before trusting a twin/triplet/reclaim result.

The goal is to prevent historical false positives such as self-read aliases
or marker-only "R/W established" claims from being treated as real progress.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
from pathlib import Path
from typing import Iterable


TANDA_RE = re.compile(r"tanda(\d+)\.md$")
CHAIN_RE = re.compile(r"INYECTADO: poopsploit_chain\.js \((\d+) bytes\)(?: sha256=([0-9a-f]{64}))?")
ALIAS_RE = re.compile(r"(?:TRUE ALIAS PAIR FOUND:|ALIAS HIT! SD=)\s*(\d+)\s*<->\s*(?:SD=)?(\d+)")
PAIR_RE = re.compile(r"\[1\]\s+pair=(\d+),(\d+)")
PT_PHASE_RE = re.compile(r"\[PT\]\s+phase\s+([a-z0-9_:-]+)\s*->\s*([a-z_]+)(?:\s+reason=([^\s]+))?", re.IGNORECASE)
STAGE1_RE = re.compile(r"RACE WON|SUCCESS! ALIAS CAPTURED")
MODE_RE = re.compile(r"STAGE \d+:\s*([^=\n]+?)(?:\s*=|$)")
RECLAIM_RE = re.compile(r"RECLAIM (?:CONFIRMED|HIT)!.*?(?:spray_sock\[(\d+)\]|spray\[(\d+)\]).*?fd=(\d+)")
RW_CLAIM_RE = re.compile(r"R/W primitive established|Stage 2 won")
KASLR_RE = re.compile(r"KASLR(?: LEAK| leaked| leak obtained| SUCCESS)", re.IGNORECASE)
CRITICAL_RE = re.compile(r"CRITICAL ERROR:\s*(.+)")
FAIL_RE = re.compile(r"(?:FAILED|failed|MISS marker|KASLR leak failed|triplet -> failed)")
TRIPLET_READY_RE = re.compile(r"triplet(?:s)? (?:-> )?(?:ready|valid|FOUND|ready:)", re.IGNORECASE)
TRIPLET_FAIL_RE = re.compile(r"triplet -> failed|triplet .*failed|triplet missing", re.IGNORECASE)
SELF_RISK_RE = re.compile(r"spray_sock\[(\d+)\].*?fd=(\d+)")


@dataclasses.dataclass
class RunAudit:
    path: Path
    tanda: int
    chain_bytes: int | None = None
    chain_sha: str | None = None
    stage1_won: bool = False
    aliases: list[tuple[int, int]] = dataclasses.field(default_factory=list)
    modes: list[str] = dataclasses.field(default_factory=list)
    reclaims: list[tuple[int | None, int]] = dataclasses.field(default_factory=list)
    pt_phases: dict[str, str] = dataclasses.field(default_factory=dict)
    pt_reasons: dict[str, str] = dataclasses.field(default_factory=dict)
    rw_claims: int = 0
    kaslr_hits: int = 0
    critical_errors: list[str] = dataclasses.field(default_factory=list)
    failures: int = 0
    triplet_ready: bool = False
    triplet_failed: bool = False
    verdict: str = "UNKNOWN"
    reasons: list[str] = dataclasses.field(default_factory=list)

    @property
    def alias_text(self) -> str:
        if not self.aliases:
            return "-"
        return ", ".join(f"{a}<->{b}" for a, b in self.aliases[:4])

    @property
    def mode_text(self) -> str:
        if not self.modes:
            return "-"
        return "; ".join(dict.fromkeys(m.strip() for m in self.modes if m.strip()))

    @property
    def pt_text(self) -> str:
        if not self.pt_phases:
            return "-"
        order = ("twins", "reclaim", "triplet", "kaslr", "slow_rw")
        keys = [key for key in order if key in self.pt_phases]
        keys.extend(key for key in self.pt_phases if key not in keys)
        return ", ".join(f"{key}:{self.pt_phases[key]}" for key in keys)


def iter_logs(log_dir: Path) -> Iterable[Path]:
    return sorted(
        log_dir.glob("tanda*.md"),
        key=lambda p: int(TANDA_RE.search(p.name).group(1)) if TANDA_RE.search(p.name) else 0,
    )


def parse_log(path: Path) -> RunAudit:
    match = TANDA_RE.search(path.name)
    tanda = int(match.group(1)) if match else -1
    audit = RunAudit(path=path, tanda=tanda)

    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if chain_match := CHAIN_RE.search(line):
            audit.chain_bytes = int(chain_match.group(1))
            if chain_match.group(2):
                audit.chain_sha = chain_match.group(2)
        if STAGE1_RE.search(line):
            audit.stage1_won = True
        if alias_match := ALIAS_RE.search(line):
            audit.aliases.append((int(alias_match.group(1)), int(alias_match.group(2))))
        if pair_match := PAIR_RE.search(line):
            pair = (int(pair_match.group(1)), int(pair_match.group(2)))
            if pair not in audit.aliases:
                audit.aliases.append(pair)
        if pt_match := PT_PHASE_RE.search(line):
            phase = pt_match.group(1).lower()
            audit.pt_phases[phase] = pt_match.group(2).lower()
            if pt_match.group(3):
                audit.pt_reasons[phase] = pt_match.group(3)
        if mode_match := MODE_RE.search(line):
            audit.modes.append(mode_match.group(1).strip())
        if reclaim_match := RECLAIM_RE.search(line):
            spray = reclaim_match.group(1) or reclaim_match.group(2)
            audit.reclaims.append((int(spray) if spray is not None else None, int(reclaim_match.group(3))))
        if RW_CLAIM_RE.search(line):
            audit.rw_claims += 1
        if KASLR_RE.search(line):
            audit.kaslr_hits += 1
        if critical_match := CRITICAL_RE.search(line):
            audit.critical_errors.append(critical_match.group(1).strip())
        if FAIL_RE.search(line):
            audit.failures += 1
        if TRIPLET_READY_RE.search(line):
            audit.triplet_ready = True
        if TRIPLET_FAIL_RE.search(line):
            audit.triplet_failed = True

    classify(audit)
    return audit


def classify(audit: RunAudit) -> None:
    """Classify logs using non-operational Luac0re-derived invariants."""
    if audit.critical_errors:
        audit.verdict = "BROKEN"
        audit.reasons.append("critical runtime error present")
        return

    if not audit.stage1_won:
        audit.verdict = "NO_STAGE1"
        audit.reasons.append("Stage 1 did not reach race-won state")
        return

    if audit.pt_phases.get("twins") == "failed":
        audit.verdict = "REJECT_SELF_ALIAS"
        audit.reasons.append("PT twins invariant explicitly failed")
        return

    if not audit.aliases:
        audit.verdict = "NO_ALIAS"
        audit.reasons.append("Stage 1 won but no true alias pair logged")
        return

    if any(a == b for a, b in audit.aliases):
        audit.verdict = "REJECT_SELF_ALIAS"
        audit.reasons.append("alias pair contains identical endpoints")
        return

    if audit.triplet_failed:
        audit.verdict = "BLOCKED_TRIPLET"
        audit.reasons.append("triplet stage explicitly failed")
        return

    if audit.pt_phases.get("triplet") in {"blocked", "failed"}:
        audit.verdict = "BLOCKED_TRIPLET"
        audit.reasons.append("PT triplet invariant blocked or failed")
        return

    # Marker-only R/W claims without triplet readiness are the historical false-positive pattern.
    if audit.rw_claims and not audit.triplet_ready and audit.pt_phases.get("slow_rw") != "ready":
        audit.verdict = "UNTRUSTED_RW_CLAIM"
        audit.reasons.append("R/W was claimed before a triplet-ready invariant appeared")
        if audit.reclaims:
            audit.reasons.append("reclaim marker exists but does not prove independent primitive")
        return

    if audit.pt_phases.get("slow_rw") == "blocked":
        audit.verdict = "RECLAIM_ONLY" if audit.reclaims or audit.pt_phases.get("reclaim") == "ready" else "FAILED_AFTER_STAGE1"
        audit.reasons.append("slow R/W was blocked by invariant guard")
        if reason := audit.pt_reasons.get("slow_rw"):
            audit.reasons.append(f"slow_rw reason: {reason}")
        return

    if (audit.triplet_ready or audit.pt_phases.get("triplet") == "ready") and (audit.reclaims or audit.pt_phases.get("reclaim") == "ready"):
        audit.verdict = "PROMISING"
        audit.reasons.append("triplet and reclaim evidence coexist")
        return

    if audit.reclaims or audit.pt_phases.get("reclaim") == "ready":
        audit.verdict = "RECLAIM_ONLY"
        audit.reasons.append("reclaim marker present without triplet readiness")
        return

    if audit.failures:
        audit.verdict = "FAILED_AFTER_STAGE1"
        audit.reasons.append("failure markers appeared after Stage 1")
        return

    audit.verdict = "STAGE1_ONLY"
    audit.reasons.append("only Stage 1 alias evidence is present")


def render_markdown(audits: list[RunAudit]) -> str:
    lines: list[str] = []
    lines.append("# Luac0re Invariant Audit for TontoJB Logs")
    lines.append("")
    lines.append("This report is generated from captured logs only. It does not execute exploit code.")
    lines.append("")
    lines.append("## Verdict Summary")
    lines.append("")
    counts: dict[str, int] = {}
    for audit in audits:
        counts[audit.verdict] = counts.get(audit.verdict, 0) + 1
    for verdict, count in sorted(counts.items()):
        lines.append(f"- **{verdict}**: {count}")
    lines.append("")
    lines.append("## Per-Tanda Audit")
    lines.append("")
    lines.append("| Tanda | Chain | Mode(s) | Alias | PT phases | Verdict | Reason |")
    lines.append("|---:|---|---|---|---|---|---|")
    for audit in audits:
        reason = "; ".join(audit.reasons).replace("|", "\\|")
        chain = str(audit.chain_bytes) if audit.chain_bytes is not None else "-"
        if audit.chain_sha:
            chain += f" / `{audit.chain_sha[:16]}`"
        lines.append(
            f"| {audit.tanda} | {chain} | {audit.mode_text} | {audit.alias_text} | {audit.pt_text} | "
            f"{audit.verdict} | {reason} |"
        )
    lines.append("")
    lines.append("## Luac0re-Derived Invariants Used")
    lines.append("")
    lines.append("- Twin evidence is insufficient if it can be explained by self-read or same-round writes.")
    lines.append("- Triplet readiness must appear before trusting later primitive claims.")
    lines.append("- Reclaim markers are useful telemetry but not proof of kernel R/W by themselves.")
    lines.append("- Critical runtime errors invalidate the tanda regardless of earlier milestones.")
    lines.append("- Failure markers after Stage 1 mean the run remains blocked after alias capture.")
    lines.append("- `[PT] phase ...` markers are authoritative for new invariant-guarded runs.")
    lines.append("- Served `sha256` values are used to correlate logs with exact chain builds.")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "Treat `UNTRUSTED_RW_CLAIM` as the historical false-positive bucket: useful for "
        "understanding heap behavior, but not acceptable as proof that TontoJB reached "
        "the Luac0re slow/fast primitive milestones."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, default=Path("logos"), help="Directory containing tanda*.md logs")
    parser.add_argument("--output", type=Path, default=None, help="Optional markdown report path")
    args = parser.parse_args()

    logs_dir = args.logs
    if not logs_dir.exists():
        raise SystemExit(f"logs directory not found: {logs_dir}")

    audits = [parse_log(path) for path in iter_logs(logs_dir)]
    report = render_markdown(audits)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)

    broken = [a for a in audits if a.verdict in {"BROKEN", "REJECT_SELF_ALIAS"}]
    return 2 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
