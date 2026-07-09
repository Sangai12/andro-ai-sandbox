"""
AndroAI Sandbox - Dynamic MITRE Mapper

This module maps observed runtime behavior indicators to
MITRE ATT&CK-style mobile technique records.

Phase 44 scope:
- Map dynamic behavior flags to technique records
- Preserve evidence source
- Keep dynamic mappings separate from static mappings
"""

from typing import Any


DYNAMIC_MITRE_RULES = {
    "network_activity_detected": {
        "technique_id": "T1437",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Runtime logs indicate network-related behavior or attempted "
            "network communication."
        ),
    },
    "webview_activity_detected": {
        "technique_id": "T1616",
        "technique_name": "Call Control",
        "tactic": "Execution",
        "description": (
            "Runtime logs indicate WebView or browser-related behavior."
        ),
    },
    "permission_denial_detected": {
        "technique_id": "T1406",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Runtime logs indicate denied access to protected Android "
            "resources or permissions."
        ),
    },
    "security_event_detected": {
        "technique_id": "T1631",
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "description": (
            "Runtime logs indicate security-relevant events such as SELinux "
            "denials, restricted access, or system interaction indicators."
        ),
    },
    "exception_detected": {
        "technique_id": "T1627",
        "technique_name": "Execution Guardrails",
        "tactic": "Defense Evasion",
        "description": (
            "Runtime exceptions may indicate environment-sensitive behavior, "
            "failed execution paths, or runtime guardrail behavior."
        ),
    },
    "crash_detected": {
        "technique_id": "T1627",
        "technique_name": "Execution Guardrails",
        "tactic": "Defense Evasion",
        "description": (
            "Application crash behavior may indicate emulator sensitivity, "
            "environment checks, or unstable execution paths."
        ),
    },
}


def map_dynamic_behavior_to_mitre(
    runtime_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Map runtime behavior summary to MITRE ATT&CK-style records.
    """

    behavior_summary = runtime_analysis.get("behavior_summary", {})
    mapped_techniques = []

    for behavior_flag, rule in DYNAMIC_MITRE_RULES.items():
        if not behavior_summary.get(behavior_flag, False):
            continue

        mapped_techniques.append(
            {
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"],
                "behavior": behavior_flag,
                "source": "dynamic",
                "description": rule["description"],
                "evidence": _get_evidence_for_behavior(
                    runtime_analysis=runtime_analysis,
                    behavior_flag=behavior_flag,
                ),
            }
        )

    return mapped_techniques


def _get_evidence_for_behavior(
    runtime_analysis: dict[str, Any],
    behavior_flag: str,
) -> list[str]:
    """
    Return supporting runtime evidence for a mapped behavior.
    """

    evidence_map = {
        "network_activity_detected": "network_indicators",
        "webview_activity_detected": "webview_indicators",
        "permission_denial_detected": "permission_denials",
        "security_event_detected": "security_indicators",
        "exception_detected": "exceptions",
        "crash_detected": "crashes",
    }

    evidence_key = evidence_map.get(behavior_flag)

    if evidence_key is None:
        return []

    return runtime_analysis.get(evidence_key, [])[:10]