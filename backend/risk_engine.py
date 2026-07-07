"""
AndroAI Sandbox - Risk Engine

Coordinates all evidence detectors.

Current scope:
- Permission detector
- Manifest detector
- Native library detector
- DEX detector

Future:
- Certificate detector
- Network detector
"""

from typing import Any

from backend.detectors.permission_detector import (
    detect_permission_findings,
)
from backend.detectors.manifest_detector import (
    detect_manifest_findings,
)
from backend.detectors.native_detector import (
    detect_native_findings,
)
from backend.detectors.dex_detector import (
    detect_dex_findings,
)


def analyze_static_findings(
    permissions: list[str],
    apk: Any,
    native_analysis: dict[str, Any],
    dex_analysis: dict[str, Any],
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

    findings.extend(
        detect_native_findings(native_analysis)
    )

    findings.extend(
        detect_dex_findings(dex_analysis)
    )

    return findings