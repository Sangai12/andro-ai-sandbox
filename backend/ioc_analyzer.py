"""
AndroAI Sandbox - IOC Analyzer

This module extracts Indicators of Compromise (IOCs)
from string analysis results.

Phase 21 scope:
- Extract domains
- Extract URLs
- Extract IP addresses
- Extract emails
- Extract suspicious platform links
- Extract cloud/service indicators
"""

from typing import Any
import re
from urllib.parse import urlparse


def extract_iocs(
    string_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract IOC categories from string analysis output.
    """

    urls = string_analysis.get("urls", [])
    ip_addresses = string_analysis.get("ip_addresses", [])
    email_addresses = string_analysis.get("email_addresses", [])

    domains: set[str] = set()
    onion_links: set[str] = set()
    telegram_links: set[str] = set()
    discord_links: set[str] = set()
    github_links: set[str] = set()
    pastebin_links: set[str] = set()
    firebase_links: set[str] = set()
    cloud_storage_links: set[str] = set()

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if domain:
            domains.add(domain)

        url_lower = url.lower()

        if ".onion" in url_lower:
            onion_links.add(url)

        if "t.me/" in url_lower or "telegram.me/" in url_lower:
            telegram_links.add(url)

        if "discord.gg/" in url_lower or "discord.com/invite/" in url_lower:
            discord_links.add(url)

        if "github.com/" in url_lower:
            github_links.add(url)

        if "pastebin.com/" in url_lower:
            pastebin_links.add(url)

        if "firebaseio.com" in url_lower or "firebaseapp.com" in url_lower:
            firebase_links.add(url)

        if any(
            cloud_keyword in url_lower
            for cloud_keyword in [
                "s3.amazonaws.com",
                "amazonaws.com",
                "storage.googleapis.com",
                "blob.core.windows.net",
                "dropbox.com",
                "onedrive.live.com",
                "drive.google.com",
            ]
        ):
            cloud_storage_links.add(url)

    crypto_wallet_patterns = [
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        r"\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b",
        r"\b0x[a-fA-F0-9]{40}\b",
    ]

    combined_text = "\n".join(
        urls + ip_addresses + email_addresses
    )

    crypto_wallets: set[str] = set()

    for pattern in crypto_wallet_patterns:
        crypto_wallets.update(
            re.findall(pattern, combined_text)
        )

    return {
        "domains": sorted(domains),
        "domain_count": len(domains),
        "urls": urls,
        "url_count": len(urls),
        "ip_addresses": ip_addresses,
        "ip_address_count": len(ip_addresses),
        "email_addresses": email_addresses,
        "email_address_count": len(email_addresses),
        "onion_links": sorted(onion_links),
        "onion_link_count": len(onion_links),
        "telegram_links": sorted(telegram_links),
        "telegram_link_count": len(telegram_links),
        "discord_links": sorted(discord_links),
        "discord_link_count": len(discord_links),
        "github_links": sorted(github_links),
        "github_link_count": len(github_links),
        "pastebin_links": sorted(pastebin_links),
        "pastebin_link_count": len(pastebin_links),
        "firebase_links": sorted(firebase_links),
        "firebase_link_count": len(firebase_links),
        "cloud_storage_links": sorted(cloud_storage_links),
        "cloud_storage_link_count": len(cloud_storage_links),
        "crypto_wallets": sorted(crypto_wallets),
        "crypto_wallet_count": len(crypto_wallets),
    }