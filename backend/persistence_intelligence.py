"""
AndroAI Sandbox - Persistence Intelligence

This module correlates runtime intelligence to identify evidence
that may indicate persistence-related behavior.

Milestone 3 scope:
- Analyze persistence-related evidence
- Correlate process, service, intent, and filesystem intelligence
- Produce evidence-based persistence indicators
- Generate analyst-friendly persistence summary
"""

from typing import Any


def analyze_persistence_intelligence(
    process_intelligence: dict[str, Any],
    service_intelligence: dict[str, Any],
    filesystem_intelligence: dict[str, Any],
    intent_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze evidence that may indicate persistence behavior.
    """

    evidence = []

    process_flags = process_intelligence.get(
        "process_flags",
        {},
    )

    service_flags = service_intelligence.get(
        "service_flags",
        {},
    )

    filesystem_flags = filesystem_intelligence.get(
        "filesystem_flags",
        {},
    )

    intent_flags = intent_intelligence.get(
        "intent_flags",
        {},
    )

    if process_flags.get("app_process_running"):
        evidence.append(
            {
                "category": "process",
                "title": "Application process remained active",
                "confidence": "medium",
            }
        )

    if service_flags.get("services_running"):
        evidence.append(
            {
                "category": "service",
                "title": "Running Android services observed",
                "confidence": "medium",
            }
        )

    if intent_flags.get("boot_related_event_detected"):
        evidence.append(
            {
                "category": "intent",
                "title": "Boot-related broadcast evidence detected",
                "confidence": "high",
            }
        )

    if filesystem_flags.get("shared_preferences_detected"):
        evidence.append(
            {
                "category": "filesystem",
                "title": "Shared Preferences activity observed",
                "confidence": "low",
            }
        )

    if filesystem_flags.get("database_activity_detected"):
        evidence.append(
            {
                "category": "filesystem",
                "title": "Database activity observed",
                "confidence": "low",
            }
        )

    confidence = _overall_confidence(evidence)

    return {
        "success": True,
        "persistence_indicator_count": len(evidence),
        "persistence_evidence": evidence,
        "overall_confidence": confidence,
        "persistence_flags": {
            "possible_persistence_detected": len(evidence) > 0,
            "boot_persistence_indicator": intent_flags.get(
                "boot_related_event_detected",
                False,
            ),
            "service_persistence_indicator": service_flags.get(
                "services_running",
                False,
            ),
            "process_persistence_indicator": process_flags.get(
                "app_process_running",
                False,
            ),
        },
        "message": "Persistence intelligence analyzed successfully.",
    }


def _overall_confidence(
    evidence: list[dict[str, Any]],
) -> str:
    """
    Calculate an overall confidence level.
    """

    if not evidence:
        return "none"

    scores = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    total = sum(
        scores.get(item.get("confidence", "low"), 1)
        for item in evidence
    )

    average = total / len(evidence)

    if average >= 2.5:
        return "high"

    if average >= 1.5:
        return "medium"

    return "low"