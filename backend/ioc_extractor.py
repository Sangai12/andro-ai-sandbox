"""
AndroAI Sandbox - IOC Extractor

This module extracts Indicators of Compromise (IOCs) from
static and dynamic analysis evidence.

Phase 42 scope:
- Extract URLs
- Extract domains
- Extract IP addresses
- Extract email addresses
- Extract crypto wallets
- Extract cloud and paste links
- Extract permissions
- Extract native libraries
- Extract certificate indicators
"""

from typing import Any


def extract_iocs_from_report(
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract IOC evidence from static and dynamic analysis results.
    """

    evidence = static_analysis.get("evidence", {})

    urls = _unique_list(evidence.get("urls", []))
    domains = _unique_list(evidence.get("domains", []))
    ip_addresses = _unique_list(evidence.get("ip_addresses", []))
    email_addresses = _unique_list(evidence.get("email_addresses", []))

    onion_links = _unique_list(evidence.get("onion_links", []))
    telegram_links = _unique_list(evidence.get("telegram_links", []))
    discord_links = _unique_list(evidence.get("discord_links", []))
    github_links = _unique_list(evidence.get("github_links", []))
    pastebin_links = _unique_list(evidence.get("pastebin_links", []))
    firebase_links = _unique_list(evidence.get("firebase_links", []))
    cloud_storage_links = _unique_list(
        evidence.get("cloud_storage_links", []),
    )
    crypto_wallets = _unique_list(evidence.get("crypto_wallets", []))

    permissions = _unique_list(evidence.get("permissions", []))
    native_libraries = _unique_list(evidence.get("native_libraries", []))
    native_architectures = _unique_list(
        evidence.get("native_architectures", []),
    )

    certificate_indicators = _extract_certificate_indicators(
        evidence.get("certificates", []),
    )

    dynamic_network_indicators = _unique_list(
        runtime_analysis.get("network_indicators", []),
    )

    dynamic_security_indicators = _unique_list(
        runtime_analysis.get("security_indicators", []),
    )

    return {
        "urls": urls,
        "url_count": len(urls),
        "domains": domains,
        "domain_count": len(domains),
        "ip_addresses": ip_addresses,
        "ip_address_count": len(ip_addresses),
        "email_addresses": email_addresses,
        "email_address_count": len(email_addresses),
        "onion_links": onion_links,
        "onion_link_count": len(onion_links),
        "telegram_links": telegram_links,
        "telegram_link_count": len(telegram_links),
        "discord_links": discord_links,
        "discord_link_count": len(discord_links),
        "github_links": github_links,
        "github_link_count": len(github_links),
        "pastebin_links": pastebin_links,
        "pastebin_link_count": len(pastebin_links),
        "firebase_links": firebase_links,
        "firebase_link_count": len(firebase_links),
        "cloud_storage_links": cloud_storage_links,
        "cloud_storage_link_count": len(cloud_storage_links),
        "crypto_wallets": crypto_wallets,
        "crypto_wallet_count": len(crypto_wallets),
        "permissions": permissions,
        "permission_count": len(permissions),
        "native_libraries": native_libraries,
        "native_library_count": len(native_libraries),
        "native_architectures": native_architectures,
        "native_architecture_count": len(native_architectures),
        "certificate_indicators": certificate_indicators,
        "certificate_indicator_count": len(certificate_indicators),
        "dynamic_network_indicators": dynamic_network_indicators,
        "dynamic_network_indicator_count": len(
            dynamic_network_indicators,
        ),
        "dynamic_security_indicators": dynamic_security_indicators,
        "dynamic_security_indicator_count": len(
            dynamic_security_indicators,
        ),
        "ioc_summary": {
            "total_network_iocs": (
                len(urls)
                + len(domains)
                + len(ip_addresses)
                + len(dynamic_network_indicators)
            ),
            "total_identity_iocs": (
                len(email_addresses)
                + len(certificate_indicators)
            ),
            "total_platform_iocs": (
                len(permissions)
                + len(native_libraries)
                + len(native_architectures)
            ),
            "total_special_iocs": (
                len(onion_links)
                + len(telegram_links)
                + len(discord_links)
                + len(github_links)
                + len(pastebin_links)
                + len(firebase_links)
                + len(cloud_storage_links)
                + len(crypto_wallets)
            ),
        },
    }


def _unique_list(values: list[Any]) -> list[str]:
    """
    Return sorted unique string values.
    """

    unique_values = {
        str(value).strip()
        for value in values
        if str(value).strip()
    }

    return sorted(unique_values)


def _extract_certificate_indicators(
    certificates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Extract useful certificate IOC fields.
    """

    indicators = []

    for certificate in certificates:
        indicators.append(
            {
                "subject": certificate.get("subject", ""),
                "issuer": certificate.get("issuer", ""),
                "serial_number": certificate.get("serial_number", ""),
                "sha1": certificate.get("sha1", ""),
                "sha256": certificate.get("sha256", ""),
            }
        )

    return indicators