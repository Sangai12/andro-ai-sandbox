"""
AndroAI Sandbox - Static Analyzer

This module performs static APK analysis.

Current scope:
- Load APK files
- Extract basic APK metadata
- Extract requested permissions
- Extract manifest components
- Extract certificate metadata
- Extract native library information
- Extract DEX metadata
- Extract string indicators
- Detect evidence-based security findings
"""

from pathlib import Path
from typing import Any

from androguard.core.apk import APK

from backend.certificate_analyzer import extract_certificate_metadata
from backend.dex_analyzer import extract_dex_metadata
from backend.native_analyzer import extract_native_libraries
from backend.string_analyzer import extract_string_indicators
from backend.risk_engine import analyze_static_findings


def extract_apk_metadata(apk_path: str | Path) -> dict[str, Any]:
    """
    Extract static metadata, permissions, manifest components,
    certificate metadata, native library information,
    DEX metadata, string indicators, and evidence-based
    security findings from an APK file.
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

    certificates = extract_certificate_metadata(apk)
    native_analysis = extract_native_libraries(apk)
    dex_analysis = extract_dex_metadata(apk)
    string_analysis = extract_string_indicators(apk)

    findings = analyze_static_findings(
        permissions=permissions,
        apk=apk,
        native_analysis=native_analysis,
        dex_analysis=dex_analysis,
    )

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

        "certificates": certificates,
        "certificate_count": len(certificates),

        "native_libraries": native_analysis["native_libraries"],
        "native_library_count": native_analysis["native_library_count"],
        "native_architectures": native_analysis["native_architectures"],

        "dex_files": dex_analysis["dex_files"],
        "dex_file_count": dex_analysis["dex_file_count"],

        "urls": string_analysis["urls"],
        "url_count": string_analysis["url_count"],

        "ip_addresses": string_analysis["ip_addresses"],
        "ip_address_count": string_analysis["ip_address_count"],

        "email_addresses": string_analysis["email_addresses"],
        "email_address_count": string_analysis["email_address_count"],

        "suspicious_commands": string_analysis["suspicious_commands"],
        "suspicious_command_count": string_analysis["suspicious_command_count"],

        "findings": findings,
        "finding_count": len(findings),
    }