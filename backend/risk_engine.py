"""
AndroAI Sandbox - Risk Engine

Coordinates all evidence detectors.

Current scope:
- Permission detector
- Manifest detector
- Native library detector
- DEX detector
- Network detector
- Certificate detector
- Code threat detector
- YARA detector
- API usage detector
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
from backend.detectors.network_detector import (
    detect_network_findings,
)
from backend.detectors.certificate_detector import (
    detect_certificate_findings,
)
from backend.detectors.code_threat_detector import (
    detect_code_threat_findings,
)
from backend.detectors.yara_detector import (
    detect_yara_findings,
)
from backend.detectors.api_usage_detector import (
    detect_api_usage_findings,
)


def analyze_static_findings(
    permissions: list[str],
    apk: Any,
    native_analysis: dict[str, Any],
    dex_analysis: dict[str, Any],
    string_analysis: dict[str, Any],
    certificates: list[dict[str, Any]],
    yara_analysis: dict[str, Any],
    api_usage_analysis: dict[str, Any],
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

    findings.extend(
        detect_network_findings(string_analysis)
    )

    findings.extend(
        detect_certificate_findings(certificates)
    )

    findings.extend(
        detect_code_threat_findings(string_analysis)
    )

    findings.extend(
        detect_yara_findings(yara_analysis)
    )

    findings.extend(
        detect_api_usage_findings(api_usage_analysis)
    )

    return findings