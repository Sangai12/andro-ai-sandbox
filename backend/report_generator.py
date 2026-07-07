"""
AndroAI Sandbox - Report Generator

This module builds a structured analysis report from
APK metadata, extracted evidence, findings, and risk results.

Phase 19 scope:
- Build consistent report object
- Keep report formatting separate from analysis logic
- Add report version metadata
"""

from datetime import UTC, datetime
from typing import Any


def build_analysis_report(
    analysis_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a structured report from analysis data.
    """

    return {
        "report_metadata": {
            "report_version": "1.0",
            "analyzer_name": "AndroAI Sandbox",
            "analyzer_version": "0.1.0",
            "generated_at": datetime.now(UTC).isoformat(),
        },
        "apk": {
            "package_name": analysis_data["package_name"],
            "version_name": analysis_data["version_name"],
            "version_code": analysis_data["version_code"],
            "min_sdk": analysis_data["min_sdk"],
            "target_sdk": analysis_data["target_sdk"],
        },
        "summary": {
            "risk_score": analysis_data["risk_score"],
            "risk_level": analysis_data["risk_level"],
            "risk_summary": analysis_data["risk_summary"],
            "total_findings": analysis_data["total_findings"],
            "severity_counts": analysis_data["severity_counts"],
        },
        "evidence": {
            "permissions": analysis_data["permissions"],
            "permission_count": analysis_data["permission_count"],
            "activities": analysis_data["activities"],
            "activity_count": analysis_data["activity_count"],
            "services": analysis_data["services"],
            "service_count": analysis_data["service_count"],
            "receivers": analysis_data["receivers"],
            "receiver_count": analysis_data["receiver_count"],
            "providers": analysis_data["providers"],
            "provider_count": analysis_data["provider_count"],
            "certificates": analysis_data["certificates"],
            "certificate_count": analysis_data["certificate_count"],
            "native_libraries": analysis_data["native_libraries"],
            "native_library_count": analysis_data["native_library_count"],
            "native_architectures": analysis_data["native_architectures"],
            "dex_files": analysis_data["dex_files"],
            "dex_file_count": analysis_data["dex_file_count"],
            "urls": analysis_data["urls"],
            "url_count": analysis_data["url_count"],
            "ip_addresses": analysis_data["ip_addresses"],
            "ip_address_count": analysis_data["ip_address_count"],
            "email_addresses": analysis_data["email_addresses"],
            "email_address_count": analysis_data["email_address_count"],
            "suspicious_commands": analysis_data["suspicious_commands"],
            "suspicious_command_count": analysis_data[
                "suspicious_command_count"
            ],
            "domains": analysis_data["domains"],
            "domain_count": analysis_data["domain_count"],
            "onion_links": analysis_data["onion_links"],
            "onion_link_count": analysis_data["onion_link_count"],
            "telegram_links": analysis_data["telegram_links"],
            "telegram_link_count": analysis_data["telegram_link_count"],
            "discord_links": analysis_data["discord_links"],
            "discord_link_count": analysis_data["discord_link_count"],
            "github_links": analysis_data["github_links"],
            "github_link_count": analysis_data["github_link_count"],
            "pastebin_links": analysis_data["pastebin_links"],
            "pastebin_link_count": analysis_data["pastebin_link_count"],
            "firebase_links": analysis_data["firebase_links"],
            "firebase_link_count": analysis_data["firebase_link_count"],
            "cloud_storage_links": analysis_data["cloud_storage_links"],
            "cloud_storage_link_count": analysis_data[
                "cloud_storage_link_count"
            ],
            "crypto_wallets": analysis_data["crypto_wallets"],
            "crypto_wallet_count": analysis_data["crypto_wallet_count"],
            "yara_matched_rules": analysis_data["yara_matched_rules"],
            "yara_match_count": analysis_data["yara_match_count"],
        },
        "findings": analysis_data["findings"],
        "finding_count": analysis_data["finding_count"],
    }