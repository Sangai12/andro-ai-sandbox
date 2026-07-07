"""
AndroAI Sandbox - Risk Engine

Coordinates all evidence detectors.

Current scope:
- Permission detector

Future:
- Manifest detector
- Certificate detector
- Native library detector
- Network detector
- DEX detector
"""


from backend.detectors.permission_detector import (
    detect_permission_findings,
)


def analyze_static_findings(
    permissions: list[str],
) -> list[dict[str, str]]:
    """
    Run all static detectors and combine their findings.
    """

    findings: list[dict[str, str]] = []

    findings.extend(
        detect_permission_findings(permissions)
    )

    return findings