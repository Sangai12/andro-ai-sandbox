"""
AndroAI Sandbox - Behavior Confidence Engine

This module calculates confidence levels for observed runtime behaviors
using outputs from existing intelligence modules.

Milestone 3 scope:
- Correlate intelligence module outputs
- Assign confidence levels to observed behaviors
- Keep scoring deterministic and evidence-based
- Prepare confidence output for reports and AI summaries
"""

from typing import Any


def calculate_behavior_confidence(
    process_intelligence: dict[str, Any],
    service_intelligence: dict[str, Any],
    network_intelligence: dict[str, Any],
    filesystem_intelligence: dict[str, Any],
    intent_intelligence: dict[str, Any],
    persistence_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate confidence levels from runtime intelligence evidence.
    """

    behavior_confidences = []

    _add_process_confidence(
        behavior_confidences,
        process_intelligence,
    )

    _add_service_confidence(
        behavior_confidences,
        service_intelligence,
    )

    _add_network_confidence(
        behavior_confidences,
        network_intelligence,
    )

    _add_filesystem_confidence(
        behavior_confidences,
        filesystem_intelligence,
    )

    _add_intent_confidence(
        behavior_confidences,
        intent_intelligence,
    )

    _add_persistence_confidence(
        behavior_confidences,
        persistence_intelligence,
    )

    return {
        "success": True,
        "behavior_confidence_count": len(behavior_confidences),
        "behavior_confidences": behavior_confidences,
        "confidence_summary": _build_confidence_summary(
            behavior_confidences,
        ),
        "overall_behavior_confidence": _overall_behavior_confidence(
            behavior_confidences,
        ),
        "message": "Behavior confidence calculated successfully.",
    }


def _add_process_confidence(
    behavior_confidences: list[dict[str, Any]],
    process_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for process behavior.
    """

    flags = process_intelligence.get("process_flags", {})

    if not flags.get("app_process_running"):
        return

    confidence = "medium"

    if flags.get("multiple_processes_detected"):
        confidence = "high"

    behavior_confidences.append(
        {
            "behavior": "process_activity",
            "confidence": confidence,
            "reason": (
                "App-related process activity was observed during runtime."
            ),
            "evidence": {
                "process_count": process_intelligence.get(
                    "process_count",
                    0,
                ),
                "child_process_count": process_intelligence.get(
                    "child_process_count",
                    0,
                ),
                "process_flags": flags,
            },
        }
    )


def _add_service_confidence(
    behavior_confidences: list[dict[str, Any]],
    service_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for service behavior.
    """

    flags = service_intelligence.get("service_flags", {})

    if not flags.get("services_running"):
        return

    confidence = "medium"

    if flags.get("foreground_service_indicator_detected"):
        confidence = "high"

    behavior_confidences.append(
        {
            "behavior": "service_activity",
            "confidence": confidence,
            "reason": (
                "App-related Android service activity was observed during runtime."
            ),
            "evidence": {
                "service_count": service_intelligence.get(
                    "service_count",
                    0,
                ),
                "service_flags": flags,
            },
        }
    )


def _add_network_confidence(
    behavior_confidences: list[dict[str, Any]],
    network_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for network behavior.
    """

    flags = network_intelligence.get("network_flags", {})

    if not flags.get("network_activity_detected"):
        return

    confidence = "medium"

    if (
        flags.get("encrypted_traffic_detected")
        or flags.get("dns_activity_detected")
        or flags.get("socket_activity_detected")
    ):
        confidence = "high"

    behavior_confidences.append(
        {
            "behavior": "network_activity",
            "confidence": confidence,
            "reason": (
                "Runtime logs contained network-related indicators."
            ),
            "evidence": {
                "total_network_indicators": network_intelligence.get(
                    "total_network_indicators",
                    0,
                ),
                "network_flags": flags,
            },
        }
    )


def _add_filesystem_confidence(
    behavior_confidences: list[dict[str, Any]],
    filesystem_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for filesystem behavior.
    """

    flags = filesystem_intelligence.get("filesystem_flags", {})

    if not flags.get("filesystem_activity_detected"):
        return

    confidence = "low"

    if (
        flags.get("database_activity_detected")
        or flags.get("shared_preferences_detected")
        or flags.get("temporary_file_activity_detected")
    ):
        confidence = "medium"

    behavior_confidences.append(
        {
            "behavior": "filesystem_activity",
            "confidence": confidence,
            "reason": (
                "Runtime evidence contained filesystem-related indicators."
            ),
            "evidence": {
                "total_filesystem_indicators": (
                    filesystem_intelligence.get(
                        "total_filesystem_indicators",
                        0,
                    )
                ),
                "filesystem_flags": flags,
            },
        }
    )


def _add_intent_confidence(
    behavior_confidences: list[dict[str, Any]],
    intent_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for intent and broadcast behavior.
    """

    flags = intent_intelligence.get("intent_flags", {})

    if not flags.get("intent_activity_detected"):
        return

    confidence = "medium"

    if (
        flags.get("boot_related_event_detected")
        or flags.get("sms_event_detected")
        or flags.get("phone_event_detected")
    ):
        confidence = "high"

    behavior_confidences.append(
        {
            "behavior": "intent_or_broadcast_activity",
            "confidence": confidence,
            "reason": (
                "Runtime logs contained Android intent or broadcast indicators."
            ),
            "evidence": {
                "total_intent_indicators": intent_intelligence.get(
                    "total_intent_indicators",
                    0,
                ),
                "intent_flags": flags,
            },
        }
    )


def _add_persistence_confidence(
    behavior_confidences: list[dict[str, Any]],
    persistence_intelligence: dict[str, Any],
) -> None:
    """
    Add confidence for persistence behavior.
    """

    flags = persistence_intelligence.get("persistence_flags", {})

    if not flags.get("possible_persistence_detected"):
        return

    confidence = persistence_intelligence.get(
        "overall_confidence",
        "low",
    )

    behavior_confidences.append(
        {
            "behavior": "possible_persistence",
            "confidence": confidence,
            "reason": (
                "Multiple runtime evidence sources may indicate persistence-related behavior."
            ),
            "evidence": {
                "persistence_indicator_count": (
                    persistence_intelligence.get(
                        "persistence_indicator_count",
                        0,
                    )
                ),
                "persistence_flags": flags,
            },
        }
    )


def _build_confidence_summary(
    behavior_confidences: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Count confidence levels.
    """

    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for item in behavior_confidences:
        confidence = item.get("confidence", "low")

        if confidence not in summary:
            confidence = "low"

        summary[confidence] += 1

    return summary


def _overall_behavior_confidence(
    behavior_confidences: list[dict[str, Any]],
) -> str:
    """
    Calculate overall behavior confidence.
    """

    if not behavior_confidences:
        return "none"

    summary = _build_confidence_summary(behavior_confidences)

    if summary["high"] >= 2:
        return "high"

    if summary["high"] == 1 or summary["medium"] >= 2:
        return "medium"

    return "low"