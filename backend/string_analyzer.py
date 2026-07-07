"""
AndroAI Sandbox - String Analyzer

This module extracts strings and indicators from APK files.

Phase 14 scope:
- Extract URLs
- Extract IP addresses
- Extract email addresses
- Extract suspicious command strings
"""

import re
from typing import Any

from androguard.core.apk import APK


def extract_string_indicators(
    apk: APK,
) -> dict[str, Any]:
    """
    Extract string-based indicators from APK files.
    """

    all_strings: set[str] = set()

    for apk_file in apk.get_files():
        try:
            if not apk_file.endswith(
                (
                    ".dex",
                    ".xml",
                    ".json",
                    ".txt",
                    ".html",
                    ".js",
                    ".properties",
                    ".so",
                )
            ):
                continue

            file_data = apk.get_file(apk_file)

            decoded_text = file_data.decode(
                "utf-8",
                errors="ignore",
            )

            for match in re.findall(
                r"[\x20-\x7E]{4,}",
                decoded_text,
            ):
                cleaned_match = match.strip()

                if cleaned_match:
                    all_strings.add(cleaned_match)

        except Exception:
            continue

    urls = sorted(
        {
            value
            for value in all_strings
            if re.fullmatch(
                r"https?://[A-Za-z0-9./_?=&:%#@+-]+",
                value,
            )
        }
    )

    ip_addresses = sorted(
        {
            value
            for value in all_strings
            if re.fullmatch(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                value,
            )
        }
    )

    email_addresses = sorted(
        {
            value
            for value in all_strings
            if re.fullmatch(
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                value,
            )
        }
    )

    suspicious_command_patterns = [
        r"/system/bin/su\b",
        r"/system/xbin/su\b",
        r"/sbin/su\b",
        r"/data/local/bin/su\b",
        r"/data/local/xbin/su\b",
        r"/data/local/su\b",
        r"\bchmod\s+[0-7]{3,4}\b",
        r"\bchown\b",
        r"\bmount\s+-o\b",
        r"\bpm\s+install\b",
        r"\bpm\s+uninstall\b",
        r"\bam\s+start\b",
        r"\bsh\s+-c\b",
        r"\bbusybox\b",
    ]

    suspicious_commands = sorted(
        {
            value
            for value in all_strings
            if any(
                re.search(
                    pattern,
                    value.lower(),
                )
                for pattern in suspicious_command_patterns
            )
        }
    )

    return {
        "url_count": len(urls),
        "urls": urls[:100],
        "ip_address_count": len(ip_addresses),
        "ip_addresses": ip_addresses[:100],
        "email_address_count": len(email_addresses),
        "email_addresses": email_addresses[:100],
        "suspicious_command_count": len(suspicious_commands),
        "suspicious_commands": suspicious_commands[:100],
    }