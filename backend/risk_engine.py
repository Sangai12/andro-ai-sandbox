"""
AndroAI Sandbox - Risk Engine

Coordinates all evidence detectors.

Current scope:
- Permission detector
- Manifest detector

Future:
- Certificate detector
- Native library detector
- Network detector
- DEX detector
"""

from typing import Any

from backend.detectors.permission_detector import (
    detect_permission_findings,
)
from backend.detectors.manifest_detector import (
    detect_manifest_findings,
)


def analyze_static_findings(
    permissions: list[str],
    apk: Any,
) -> list[dict[str, str]]:
    """
    Run all static detectors and combine their findings.
    """

    findings: list[dict[str, str]] = []

    findings.extend(
        detect_permission_findings(permissions)
    )

    findings.extend(
        detect_manifest_findings(apk)
    )

    return findings