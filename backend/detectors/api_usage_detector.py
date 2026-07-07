"""
AndroAI Sandbox - API Usage Detector

This module converts sensitive API usage indicators into
evidence-based findings.

Phase 22.2 scope:
- Detect sensitive API usage categories
- Convert API usage evidence into findings
"""

from typing import Any


def detect_api_usage_findings(
    api_usage_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Convert API usage indicators into findings.
    """

    findings: list[dict[str, str]] = []

    api_usage = api_usage_analysis.get("api_usage", {})

    severity_by_category = {
        "runtime_execution": "high",
        "dynamic_loading": "high",
        "reflection": "medium",
        "webview_bridge": "medium",
        "sms_telephony": "high",
        "accessibility_device_admin": "high",
        "crypto_keystore": "low",
        "package_inspection": "medium",
    }

    title_by_category = {
        "runtime_execution": "Runtime Execution API Usage Detected",
        "dynamic_loading": "Dynamic Code Loading API Usage Detected",
        "reflection": "Reflection API Usage Detected",
        "webview_bridge": "WebView Bridge API Usage Detected",
        "sms_telephony": "SMS or Telephony API Usage Detected",
        "accessibility_device_admin": (
            "Accessibility or Device Admin API Usage Detected"
        ),
        "crypto_keystore": "Cryptography or Keystore API Usage Detected",
        "package_inspection": "Package Inspection API Usage Detected",
    }

    for category, matched_apis in api_usage.items():
        if not matched_apis:
            continue

        findings.append(
            {
                "id": f"API_USAGE_{category.upper()}",
                "title": title_by_category.get(
                    category,
                    "Sensitive API Usage Detected",
                ),
                "severity": severity_by_category.get(category, "medium"),
                "evidence_type": "api_usage",
                "evidence": ",".join(matched_apis),
            }
        )

    return findings