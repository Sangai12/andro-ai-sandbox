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
- Extract IOC indicators
- Extract API usage indicators
- Extract YARA scan results
- Detect evidence-based security findings
- Calculate overall risk score
- Generate risk summary
- Build structured analysis report
"""

from pathlib import Path
from typing import Any

from androguard.core.apk import APK

from backend.api_usage_analyzer import extract_api_usage
from backend.certificate_analyzer import extract_certificate_metadata
from backend.dex_analyzer import extract_dex_metadata
from backend.ioc_analyzer import extract_iocs
from backend.native_analyzer import extract_native_libraries
from backend.report_generator import build_analysis_report
from backend.risk_engine import analyze_static_findings
from backend.risk_score import calculate_risk_score
from backend.risk_summary import generate_risk_summary
from backend.string_analyzer import extract_string_indicators
from backend.yara_analyzer import scan_with_yara


def extract_apk_metadata(apk_path: str | Path) -> dict[str, Any]:
    """
    Extract static metadata, evidence, findings, risk score,
    risk summary, and structured report from an APK file.
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
    ioc_analysis = extract_iocs(string_analysis)
    api_usage_analysis = extract_api_usage(string_analysis)

    yara_analysis = scan_with_yara(
        apk_path=apk_file,
        rule_file=Path("rules/android_basic_rules.yar"),
    )

    findings = analyze_static_findings(
        permissions=permissions,
        apk=apk,
        native_analysis=native_analysis,
        dex_analysis=dex_analysis,
        string_analysis=string_analysis,
        certificates=certificates,
        yara_analysis=yara_analysis,
        api_usage_analysis=api_usage_analysis,
    )

    risk_analysis = calculate_risk_score(findings)
    risk_summary = generate_risk_summary(
        risk_analysis=risk_analysis,
        findings=findings,
    )

    analysis_data = {
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

        "domains": ioc_analysis["domains"],
        "domain_count": ioc_analysis["domain_count"],
        "onion_links": ioc_analysis["onion_links"],
        "onion_link_count": ioc_analysis["onion_link_count"],
        "telegram_links": ioc_analysis["telegram_links"],
        "telegram_link_count": ioc_analysis["telegram_link_count"],
        "discord_links": ioc_analysis["discord_links"],
        "discord_link_count": ioc_analysis["discord_link_count"],
        "github_links": ioc_analysis["github_links"],
        "github_link_count": ioc_analysis["github_link_count"],
        "pastebin_links": ioc_analysis["pastebin_links"],
        "pastebin_link_count": ioc_analysis["pastebin_link_count"],
        "firebase_links": ioc_analysis["firebase_links"],
        "firebase_link_count": ioc_analysis["firebase_link_count"],
        "cloud_storage_links": ioc_analysis["cloud_storage_links"],
        "cloud_storage_link_count": ioc_analysis[
            "cloud_storage_link_count"
        ],
        "crypto_wallets": ioc_analysis["crypto_wallets"],
        "crypto_wallet_count": ioc_analysis["crypto_wallet_count"],

        "api_usage": api_usage_analysis["api_usage"],
        "api_usage_categories": api_usage_analysis["api_usage_categories"],
        "api_usage_category_count": api_usage_analysis[
            "api_usage_category_count"
        ],

        "yara_matched_rules": yara_analysis["matched_rules"],
        "yara_match_count": yara_analysis["match_count"],

        "risk_score": risk_analysis["risk_score"],
        "risk_level": risk_analysis["risk_level"],
        "risk_summary": risk_summary,
        "severity_counts": risk_analysis["severity_counts"],
        "total_findings": risk_analysis["total_findings"],

        "findings": findings,
        "finding_count": len(findings),
    }

    return build_analysis_report(analysis_data)