"""
AndroAI Sandbox - YARA Analyzer

This module scans APK files using YARA rules.

Phase 20.1 scope:
- Load YARA rules
- Scan APK files
- Return matched rule names
"""

from pathlib import Path
from typing import Any

import yara


def scan_with_yara(
    apk_path: str | Path,
    rule_file: str | Path,
) -> dict[str, Any]:
    """
    Scan an APK file using a YARA rule file.
    """

    try:
        rules = yara.compile(filepath=str(rule_file))
        matches = rules.match(str(apk_path))

        return {
            "matched_rules": sorted(
                match.rule
                for match in matches
            ),
            "match_count": len(matches),
        }

    except yara.Error:
        return {
            "matched_rules": [],
            "match_count": 0,
        }