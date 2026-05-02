#!/usr/bin/env python3
"""Fixture tests for the offline Luac0re invariant audit.

These tests are intentionally PS5-free. They validate that known log patterns
continue to land in the expected verdict buckets before we trust a live tanda.
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from luacore_invariant_audit import parse_log  # noqa: E402


FIXTURE_DIR = ROOT / "tests" / "fixtures" / "luacore_audit"

EXPECTED_VERDICTS = {
    "tanda1.md": "NO_STAGE1",
    "tanda2.md": "UNTRUSTED_RW_CLAIM",
    "tanda3.md": "RECLAIM_ONLY",
    "tanda4.md": "PROMISING",
    "tanda5.md": "BROKEN",
    "tanda6.md": "REJECT_SELF_ALIAS",
}


def main() -> int:
    failures: list[str] = []

    for name, expected in EXPECTED_VERDICTS.items():
        audit = parse_log(FIXTURE_DIR / name)
        if audit.verdict != expected:
            failures.append(
                f"{name}: expected {expected}, got {audit.verdict} "
                f"({'; '.join(audit.reasons)})"
            )

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    print(f"PASS {len(EXPECTED_VERDICTS)} luacore invariant audit fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
