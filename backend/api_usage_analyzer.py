"""
AndroAI Sandbox - API Usage Analyzer

This module detects sensitive Android and Java API usage
from extracted string indicators.

Phase 22 scope:
- Detect runtime execution APIs
- Detect dynamic loading APIs
- Detect reflection APIs
- Detect WebView bridge APIs
- Detect SMS/telephony APIs
- Detect accessibility/device admin APIs
- Detect crypto/key APIs
- Detect package inspection APIs
"""

from typing import Any


def extract_api_usage(
    string_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract sensitive API usage indicators from string analysis output.
    """

    searchable_values: list[str] = []

    for key in [
        "urls",
        "ip_addresses",
        "email_addresses",
        "suspicious_commands",
    ]:
        searchable_values.extend(string_analysis.get(key, []))

    combined_text = "\n".join(searchable_values).lower()

    api_rules = {
        "runtime_execution": [
            "runtime.exec",
            "processbuilder",
            "java.lang.runtime",
        ],
        "dynamic_loading": [
            "dexclassloader",
            "pathclassloader",
            "loadclass",
            "system.load",
            "system.loadlibrary",
        ],
        "reflection": [
            "class.forname",
            "method.invoke",
            "getdeclaredmethod",
            "getdeclaredfield",
        ],
        "webview_bridge": [
            "addjavascriptinterface",
            "setjavascriptenabled",
            "webview",
        ],
        "sms_telephony": [
            "smsmanager",
            "sendtextmessage",
            "telephonymanager",
            "getdeviceid",
            "getsubscriberid",
            "getline1number",
        ],
        "accessibility_device_admin": [
            "accessibilityservice",
            "devicepolicymanager",
            "bind_device_admin",
        ],
        "crypto_keystore": [
            "cipher.getinstance",
            "secretkeyspec",
            "keystore",
            "messageDigest",
            "javax.crypto",
        ],
        "package_inspection": [
            "packagemanager",
            "getinstalledpackages",
            "getinstalledapplications",
            "queryintentactivities",
        ],
    }

    api_usage: dict[str, list[str]] = {}

    for category, keywords in api_rules.items():
        matches = sorted(
            {
                keyword
                for keyword in keywords
                if keyword.lower() in combined_text
            }
        )

        api_usage[category] = matches

    matched_categories = sorted(
        category
        for category, matches in api_usage.items()
        if matches
    )

    return {
        "api_usage": api_usage,
        "api_usage_categories": matched_categories,
        "api_usage_category_count": len(matched_categories),
    }