"""
AndroAI Sandbox - Intent Intelligence

This module analyzes runtime evidence for Android intent and
broadcast-related behavior.

Milestone 2 scope:
- Analyze runtime intent and broadcast indicators
- Classify boot, package, SMS, phone, connectivity, and activity events
- Summarize intent-related runtime behavior
- Produce analyst-friendly intent intelligence
"""

from typing import Any


def analyze_intent_intelligence(
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze runtime log indicators for Android intents and broadcasts.
    """

    indicators = _collect_candidate_indicators(runtime_analysis)

    boot_events = []
    package_events = []
    sms_events = []
    phone_events = []
    connectivity_events = []
    activity_events = []
    broadcast_events = []
    other = []

    for indicator in indicators:
        text = str(indicator).lower()

        if "boot_completed" in text or "locked_boot_completed" in text:
            boot_events.append(indicator)

        elif "package_added" in text or "package_removed" in text:
            package_events.append(indicator)

        elif "sms" in text or "mms" in text:
            sms_events.append(indicator)

        elif "phone_state" in text or "call" in text:
            phone_events.append(indicator)

        elif "connectivity" in text or "network" in text:
            connectivity_events.append(indicator)

        elif "activity" in text or "am_start" in text or "start u" in text:
            activity_events.append(indicator)

        elif "broadcast" in text or "intent" in text:
            broadcast_events.append(indicator)

        else:
            other.append(indicator)

    return {
        "success": True,
        "total_intent_indicators": len(indicators),
        "boot_event_count": len(boot_events),
        "package_event_count": len(package_events),
        "sms_event_count": len(sms_events),
        "phone_event_count": len(phone_events),
        "connectivity_event_count": len(connectivity_events),
        "activity_event_count": len(activity_events),
        "broadcast_event_count": len(broadcast_events),
        "other_count": len(other),
        "boot_events": boot_events[:20],
        "package_events": package_events[:20],
        "sms_events": sms_events[:20],
        "phone_events": phone_events[:20],
        "connectivity_events": connectivity_events[:20],
        "activity_events": activity_events[:20],
        "broadcast_events": broadcast_events[:20],
        "other": other[:20],
        "intent_flags": {
            "intent_activity_detected": len(indicators) > 0,
            "boot_related_event_detected": len(boot_events) > 0,
            "package_event_detected": len(package_events) > 0,
            "sms_event_detected": len(sms_events) > 0,
            "phone_event_detected": len(phone_events) > 0,
            "connectivity_event_detected": len(connectivity_events) > 0,
            "activity_launch_event_detected": len(activity_events) > 0,
            "broadcast_event_detected": len(broadcast_events) > 0,
        },
        "message": "Intent intelligence analyzed successfully.",
    }


def _collect_candidate_indicators(
    runtime_analysis: dict[str, Any],
) -> list[str]:
    """
    Collect likely intent/broadcast-related indicators from runtime logs.
    """

    candidate_keys = [
        "security_indicators",
        "network_indicators",
        "warnings",
        "errors",
        "exceptions",
    ]

    keywords = [
        "intent",
        "broadcast",
        "receiver",
        "boot_completed",
        "locked_boot_completed",
        "package_added",
        "package_removed",
        "sms",
        "mms",
        "phone_state",
        "connectivity",
        "activity",
        "am_start",
        "start u",
    ]

    candidates = []

    for key in candidate_keys:
        for value in runtime_analysis.get(key, []):
            text = str(value).lower()

            if any(keyword in text for keyword in keywords):
                candidates.append(str(value))

    return _unique_list(candidates)


def _unique_list(
    values: list[str],
) -> list[str]:
    """
    Return sorted unique values.
    """

    return sorted(
        {
            value.strip()
            for value in values
            if value.strip()
        }
    )