"""
AndroAI Sandbox - Network Detector

This module evaluates extracted network indicators and returns
evidence-based findings.

Phase 15 scope:
- Detect HTTP URLs
- Detect localhost URLs
- Detect private IP addresses
- Detect placeholder/test domains
"""

import ipaddress
from typing import Any


def _is_low_value_reference_url(url: str) -> bool:
    """
    Filter common reference, certificate, schema, and documentation URLs.
    """

    low_value_keywords = [
        "ocsp.",
        "/ocsp",
        "crl.",
        "/crl",
        "cert",
        "certificate",
        "pki",
        "schema",
        "schemas.",
        "w3.org",
        "webrtc.org",
        "apache.org/licenses",
        "ietf.org",
        "mozilla.org/mpl",

        # Added filters
        "cps",
        "/cps",
        "dtd",
        "policy",
        "repository",
        "rpa",
        "documentos",
        "fineid.fi",
        "evrotrust.com/cps",
    ]

    url_lower = url.lower()

    return any(
        keyword in url_lower
        for keyword in low_value_keywords
    )


def detect_network_findings(
    string_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Analyze extracted URLs and IP addresses.
    """

    findings: list[dict[str, str]] = []

    urls = string_analysis.get("urls", [])
    ip_addresses = string_analysis.get("ip_addresses", [])

    for url in urls:
        if _is_low_value_reference_url(url):
            continue

        if url.startswith("http://"):
            findings.append(
                {
                    "id": "NETWORK_HTTP_URL",
                    "title": "Unencrypted HTTP URL Detected",
                    "severity": "medium",
                    "evidence_type": "url",
                    "evidence": url,
                }
            )

        if "localhost" in url or "127.0.0.1" in url:
            findings.append(
                {
                    "id": "NETWORK_LOCALHOST_URL",
                    "title": "Localhost URL Detected",
                    "severity": "low",
                    "evidence_type": "url",
                    "evidence": url,
                }
            )

        if "example.com" in url:
            findings.append(
                {
                    "id": "NETWORK_PLACEHOLDER_DOMAIN",
                    "title": "Placeholder Domain Detected",
                    "severity": "low",
                    "evidence_type": "url",
                    "evidence": url,
                }
            )

    for ip_address in ip_addresses:
        try:
            parsed_ip = ipaddress.ip_address(ip_address)

            if parsed_ip.is_private:
                findings.append(
                    {
                        "id": "NETWORK_PRIVATE_IP",
                        "title": "Private IP Address Detected",
                        "severity": "low",
                        "evidence_type": "ip_address",
                        "evidence": ip_address,
                    }
                )

            if parsed_ip.is_loopback:
                findings.append(
                    {
                        "id": "NETWORK_LOOPBACK_IP",
                        "title": "Loopback IP Address Detected",
                        "severity": "low",
                        "evidence_type": "ip_address",
                        "evidence": ip_address,
                    }
                )

        except ValueError:
            continue

    return findings