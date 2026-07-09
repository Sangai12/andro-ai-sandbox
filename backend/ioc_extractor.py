"""
AndroAI Sandbox - IOC Extractor

This module extracts, filters, and classifies Indicators of Compromise
from static and dynamic analysis evidence.

Phase 42 and Phase 43 scope:
- Extract URLs
- Extract domains
- Extract IP addresses
- Extract email addresses
- Extract crypto wallets
- Extract cloud and paste links
- Extract permissions
- Extract native libraries
- Extract certificate indicators
- Filter obvious placeholder/local artifacts
- Classify IOCs for analyst use
"""

from typing import Any


PLACEHOLDER_VALUES = {
    "example.com",
    "foo@bar.com",
    "your.email@example.org",
    "localhost",
    "localhost:",
    "127.0.0.1",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.0.1",
    "%s",
    "app.",
    "app.%s",
}


NOISY_DOMAIN_PREFIXES = (
    "www.w3.org",
    "schemas.android.com",
    "ns.adobe.com",
)


def extract_iocs_from_report(
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract IOC evidence from static and dynamic analysis results.
    """

    evidence = static_analysis.get("evidence", {})

    urls = _filter_noise(_unique_list(evidence.get("urls", [])))
    domains = _filter_noise(_unique_list(evidence.get("domains", [])))
    ip_addresses = _filter_noise(_unique_list(evidence.get("ip_addresses", [])))
    email_addresses = _filter_noise(
        _unique_list(evidence.get("email_addresses", []))
    )

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

    classified_iocs = _classify_iocs(
        urls=urls,
        domains=domains,
        ip_addresses=ip_addresses,
        email_addresses=email_addresses,
        permissions=permissions,
        native_libraries=native_libraries,
        certificate_indicators=certificate_indicators,
        dynamic_network_indicators=dynamic_network_indicators,
        dynamic_security_indicators=dynamic_security_indicators,
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
        "classified_iocs": classified_iocs,
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
            "classified_ioc_count": len(classified_iocs),
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


def _filter_noise(values: list[str]) -> list[str]:
    """
    Remove obvious local, placeholder, and documentation artifacts.
    """

    filtered_values = []

    for value in values:
        lowered_value = value.lower().strip()

        if lowered_value in PLACEHOLDER_VALUES:
            continue

        if any(
            lowered_value.startswith(prefix)
            for prefix in NOISY_DOMAIN_PREFIXES
        ):
            continue

        if "example." in lowered_value:
            continue

        if "localhost" in lowered_value:
            continue

        if "127.0.0.1" in lowered_value:
            continue

        filtered_values.append(value)

    return filtered_values


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


def _classify_iocs(
    urls: list[str],
    domains: list[str],
    ip_addresses: list[str],
    email_addresses: list[str],
    permissions: list[str],
    native_libraries: list[str],
    certificate_indicators: list[dict[str, Any]],
    dynamic_network_indicators: list[str],
    dynamic_security_indicators: list[str],
) -> list[dict[str, Any]]:
    """
    Build classified IOC records.
    """

    classified_iocs = []

    for url in urls:
        classified_iocs.append(
            {
                "type": "url",
                "category": "network",
                "value": url,
                "source": "static",
            }
        )

    for domain in domains:
        classified_iocs.append(
            {
                "type": "domain",
                "category": "network",
                "value": domain,
                "source": "static",
            }
        )

    for ip_address in ip_addresses:
        classified_iocs.append(
            {
                "type": "ip_address",
                "category": "network",
                "value": ip_address,
                "source": "static",
            }
        )

    for email_address in email_addresses:
        classified_iocs.append(
            {
                "type": "email_address",
                "category": "identity",
                "value": email_address,
                "source": "static",
            }
        )

    for permission in permissions:
        classified_iocs.append(
            {
                "type": "permission",
                "category": "platform",
                "value": permission,
                "source": "static",
            }
        )

    for native_library in native_libraries:
        classified_iocs.append(
            {
                "type": "native_library",
                "category": "platform",
                "value": native_library,
                "source": "static",
            }
        )

    for certificate in certificate_indicators:
        classified_iocs.append(
            {
                "type": "certificate",
                "category": "certificate",
                "value": certificate,
                "source": "static",
            }
        )

    for runtime_network in dynamic_network_indicators:
        classified_iocs.append(
            {
                "type": "runtime_network_log",
                "category": "runtime",
                "value": runtime_network,
                "source": "dynamic",
            }
        )

    for runtime_security in dynamic_security_indicators:
        classified_iocs.append(
            {
                "type": "runtime_security_log",
                "category": "runtime",
                "value": runtime_security,
                "source": "dynamic",
            }
        )

    return classified_iocs