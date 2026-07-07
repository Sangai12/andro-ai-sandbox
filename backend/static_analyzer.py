"""
AndroAI Sandbox - Static Analyzer

This module performs static APK analysis.

Current scope:
- Load APK files
- Extract basic APK metadata
- Extract requested permissions
- Extract manifest components
- Detect evidence-based security findings
"""

from pathlib import Path
from typing import Any

from androguard.core.apk import APK

from backend.risk_engine import analyze_static_findings


def extract_apk_metadata(apk_path: str | Path) -> dict[str, Any]:
    """
    Extract static metadata, permissions, manifest components,
    and evidence-based security findings from an APK file.

    Args:
        apk_path: Path to the APK file.

    Returns:
        Dictionary containing APK metadata, permissions,
        manifest components, and security findings.
    """
    apk_file = Path(apk_path)

    if not apk_file.exists():
        raise FileNotFoundError(f"APK file not found: {apk_file}")

    apk = APK(str(apk_file))

    permissions = apk.get_permissions()
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    findings = analyze_static_findings(permissions)

    return {
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),

        "permissions": permissions,
        "permission_count": len(permissions),

        "activities": activities,
        "activity_count": len(activities),

        "services": services,
        "service_count": len(services),

        "receivers": receivers,
        "receiver_count": len(receivers),

        "providers": providers,
        "provider_count": len(providers),

        "findings": findings,
        "finding_count": len(findings),
    }