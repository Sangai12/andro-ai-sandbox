"""
AndroAI Sandbox - Persistence Intelligence

This module correlates runtime intelligence to identify evidence
that may indicate persistence-related behavior.

Current scope:
- Analyze persistence-related evidence
- Correlate process, service, intent, and filesystem intelligence
- Avoid treating normal active processes as persistence
- Require stronger corroborating evidence
- Produce evidence-based persistence indicators
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

    app_process_running = process_flags.get(
        "app_process_running",
        False,
    )

    services_running = service_flags.get(
        "services_running",
        False,
    )

    boot_event_detected = intent_flags.get(
        "boot_related_event_detected",
        False,
    )

    shared_preferences_detected = filesystem_flags.get(
        "shared_preferences_detected",
        False,
    )

    database_activity_detected = filesystem_flags.get(
        "database_activity_detected",
        False,
    )

    state_storage_detected = (
        shared_preferences_detected
        or database_activity_detected
    )

    correlated_background_activity = (
        app_process_running
        and services_running
    )

    possible_persistence_detected = (
        boot_event_detected
        or (
            correlated_background_activity
            and state_storage_detected
        )
    )

    if boot_event_detected:
        evidence.append(
            {
                "category": "intent",
                "title": "Boot-related broadcast evidence detected",
                "confidence": "high",
                "reason": (
                    "A boot-related Android event was observed during "
                    "runtime analysis."
                ),
            }
        )

    if (
        possible_persistence_detected
        and correlated_background_activity
    ):
        evidence.append(
            {
                "category": "runtime",
                "title": (
                    "Application process and service activity "
                    "were observed together"
                ),
                "confidence": "medium",
                "reason": (
                    "The application had both an active process and "
                    "running service evidence."
                ),
            }
        )

    if (
        possible_persistence_detected
        and state_storage_detected
    ):
        evidence.append(
            {
                "category": "filesystem",
                "title": "Application state-storage activity observed",
                "confidence": "low",
                "reason": (
                    "Shared Preferences or database evidence was observed "
                    "alongside stronger persistence-related indicators."
                ),
            }
        )

    confidence = _overall_confidence(evidence)

    return {
        "success": True,
        "persistence_indicator_count": len(evidence),
        "persistence_evidence": evidence,
        "overall_confidence": confidence,
        "persistence_flags": {
            "possible_persistence_detected": (
                possible_persistence_detected
            ),
            "boot_persistence_indicator": boot_event_detected,
            "service_persistence_indicator": (
                services_running
                and possible_persistence_detected
            ),
            "process_persistence_indicator": (
                app_process_running
                and possible_persistence_detected
            ),
            "state_storage_supporting_indicator": (
                state_storage_detected
                and possible_persistence_detected
            ),
            "active_process_observed": app_process_running,
            "running_service_observed": services_running,
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