"""
AndroAI Sandbox - Code Threat Detector

This module evaluates extracted strings and returns
evidence-based code/threat findings.

Phase 17 scope:
- Detect Frida indicators
- Detect Magisk indicators
- Detect Xposed indicators
- Detect root-related indicators
- Detect dynamic loading indicators
- Detect reflection indicators
- Detect crypto indicators
- Detect WebView JavaScript bridge indicators
"""

from typing import Any


def detect_code_threat_findings(
    string_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Analyze extracted strings for code and threat indicators.
    """

    findings: list[dict[str, str]] = []

    indicator_rules = [
        {
            "id": "CODE_FRIDA_INDICATOR",
            "title": "Frida Indicator Detected",
            "severity": "high",
            "keywords": ["frida", "gum-js-loop", "frida-agent"],
        },
        {
            "id": "CODE_MAGISK_INDICATOR",
            "title": "Magisk Indicator Detected",
            "severity": "high",
            "keywords": ["magisk", "zygisk"],
        },
        {
            "id": "CODE_XPOSED_INDICATOR",
            "title": "Xposed Indicator Detected",
            "severity": "high",
            "keywords": ["xposed", "lsposed"],
        },
        {
            "id": "CODE_ROOT_INDICATOR",
            "title": "Root Indicator Detected",
            "severity": "medium",
            "keywords": [
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/local/bin/su",
                "/data/local/xbin/su",
                "/data/local/su",
                "rootbeer",
            ],
        },
        {
            "id": "CODE_DYNAMIC_LOADING",
            "title": "Dynamic Code Loading Indicator Detected",
            "severity": "high",
            "keywords": [
                "dexclassloader",
                "pathclassloader",
                "loadclass",
                "loadlibrary",
                "system.load",
            ],
        },
        {
            "id": "CODE_REFLECTION",
            "title": "Reflection Indicator Detected",
            "severity": "medium",
            "keywords": [
                "class.forname",
                "method.invoke",
                "getdeclaredmethod",
                "getdeclaredfield",
            ],
        },
        {
            "id": "CODE_CRYPTO_USAGE",
            "title": "Cryptography API Indicator Detected",
            "severity": "low",
            "keywords": [
                "cipher.getinstance",
                "secretkeyspec",
                "aes/",
                "rsa/",
                "messageDigest",
                "base64",
            ],
        },
        {
            "id": "CODE_WEBVIEW_JS_BRIDGE",
            "title": "WebView JavaScript Bridge Indicator Detected",
            "severity": "medium",
            "keywords": [
                "addjavascriptinterface",
                "setjavascriptenabled",
                "webview",
            ],
        },
    ]

    searchable_values: list[str] = []

    for key in [
        "urls",
        "ip_addresses",
        "email_addresses",
        "suspicious_commands",
    ]:
        searchable_values.extend(string_analysis.get(key, []))

    for rule in indicator_rules:
        for value in searchable_values:
            value_lower = value.lower()

            for keyword in rule["keywords"]:
                if keyword.lower() in value_lower:
                    findings.append(
                        {
                            "id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "evidence_type": "code_string",
                            "evidence": value,
                        }
                    )
                    break

    return findings