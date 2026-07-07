"""
AndroAI Sandbox - Permission Detector

This module evaluates APK permissions against the
permission rule database and returns evidence-based findings.
"""

from backend.rules.permission_rules import PERMISSION_RULES


def detect_permission_findings(
    permissions: list[str],
) -> list[dict[str, str]]:
    """
    Evaluate APK permissions against the configured rules.
    """

    findings: list[dict[str, str]] = []

    for permission in permissions:
        rule = PERMISSION_RULES.get(permission)

        if rule is None:
            continue

        findings.append(
            {
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "evidence_type": "permission",
                "evidence": permission,
            }
        )

    return findings