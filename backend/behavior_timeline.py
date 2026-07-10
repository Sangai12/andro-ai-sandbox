"""
AndroAI Sandbox - Behavior Timeline

This module builds an analyst-friendly behavioral timeline from
the analysis workflow output.

Milestone 3 scope:
- Build timeline events from pipeline workflow sections
- Summarize install, launch, wait, behavior, process, service, network,
  filesystem, intent, persistence, and report events
- Keep events evidence-based
- Prepare for future report and dashboard timeline views
"""

from datetime import UTC, datetime
from typing import Any


def build_behavior_timeline(
    workflow: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a behavior timeline from workflow evidence.
    """

    events = []

    _add_workflow_event(
        events=events,
        stage="clear_logcat",
        title="Logcat buffer cleared",
        source=workflow.get("clear_logcat", {}),
    )

    _add_workflow_event(
        events=events,
        stage="install",
        title="APK installation attempted",
        source=workflow.get("install", {}),
    )

    _add_workflow_event(
        events=events,
        stage="launch",
        title="Application launch attempted",
        source=workflow.get("launch", {}),
    )

    _add_wait_event(
        events=events,
        wait_result=workflow.get("wait", {}),
    )

    _add_behavior_event(
        events=events,
        behavior_analysis=workflow.get("behavior_analysis", {}),
    )

    _add_process_event(
        events=events,
        process_intelligence=workflow.get("process_intelligence", {}),
    )

    _add_service_event(
        events=events,
        service_intelligence=workflow.get("service_intelligence", {}),
    )

    _add_network_event(
        events=events,
        network_intelligence=workflow.get("network_intelligence", {}),
    )

    _add_filesystem_event(
        events=events,
        filesystem_intelligence=workflow.get("filesystem_intelligence", {}),
    )

    _add_intent_event(
        events=events,
        intent_intelligence=workflow.get("intent_intelligence", {}),
    )

    _add_persistence_event(
        events=events,
        persistence_intelligence=workflow.get(
            "persistence_intelligence",
            {},
        ),
    )

    _add_report_event(
        events=events,
        final_report=workflow.get("final_report", {}),
    )

    return {
        "success": True,
        "event_count": len(events),
        "events": events,
        "timeline_summary": _build_timeline_summary(events),
        "generated_at": datetime.now(UTC).isoformat(),
        "message": "Behavior timeline generated successfully.",
    }


def _add_workflow_event(
    events: list[dict[str, Any]],
    stage: str,
    title: str,
    source: dict[str, Any],
) -> None:
    """
    Add a simple workflow event if source exists.
    """

    if not source:
        return

    events.append(
        {
            "stage": stage,
            "title": title,
            "success": source.get("success", False),
            "severity": "info",
            "evidence": {
                "message": source.get("message", ""),
                "stdout": source.get("stdout", ""),
                "stderr": source.get("stderr", ""),
            },
        }
    )


def _add_wait_event(
    events: list[dict[str, Any]],
    wait_result: dict[str, Any],
) -> None:
    """
    Add runtime wait event.
    """

    if not wait_result:
        return

    events.append(
        {
            "stage": "runtime_wait",
            "title": "Runtime observation window completed",
            "success": wait_result.get("success", False),
            "severity": "info",
            "evidence": wait_result,
        }
    )


def _add_behavior_event(
    events: list[dict[str, Any]],
    behavior_analysis: dict[str, Any],
) -> None:
    """
    Add behavior analysis event.
    """

    if not behavior_analysis:
        return

    events.append(
        {
            "stage": "behavior_analysis",
            "title": "Runtime behavior snapshot analyzed",
            "success": behavior_analysis.get("success", False),
            "severity": "info",
            "evidence": {
                "app_active": behavior_analysis.get("app_active", False),
                "process_count": behavior_analysis.get("process_count", 0),
                "running_service_count": behavior_analysis.get(
                    "running_service_count",
                    0,
                ),
                "behavior_flags": behavior_analysis.get(
                    "behavior_flags",
                    {},
                ),
            },
        }
    )


def _add_process_event(
    events: list[dict[str, Any]],
    process_intelligence: dict[str, Any],
) -> None:
    """
    Add process intelligence event.
    """

    if not process_intelligence:
        return

    events.append(
        {
            "stage": "process_intelligence",
            "title": "Runtime process intelligence generated",
            "success": process_intelligence.get("success", False),
            "severity": (
                "medium"
                if process_intelligence.get(
                    "child_process_count",
                    0,
                )
                > 0
                else "info"
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
                "process_flags": process_intelligence.get(
                    "process_flags",
                    {},
                ),
            },
        }
    )


def _add_service_event(
    events: list[dict[str, Any]],
    service_intelligence: dict[str, Any],
) -> None:
    """
    Add service intelligence event.
    """

    if not service_intelligence:
        return

    events.append(
        {
            "stage": "service_intelligence",
            "title": "Runtime service intelligence generated",
            "success": service_intelligence.get("success", False),
            "severity": (
                "medium"
                if service_intelligence.get(
                    "service_count",
                    0,
                )
                > 0
                else "info"
            ),
            "evidence": {
                "service_count": service_intelligence.get(
                    "service_count",
                    0,
                ),
                "service_flags": service_intelligence.get(
                    "service_flags",
                    {},
                ),
            },
        }
    )


def _add_network_event(
    events: list[dict[str, Any]],
    network_intelligence: dict[str, Any],
) -> None:
    """
    Add network intelligence event.
    """

    if not network_intelligence:
        return

    events.append(
        {
            "stage": "network_intelligence",
            "title": "Runtime network intelligence generated",
            "success": network_intelligence.get("success", False),
            "severity": (
                "medium"
                if network_intelligence.get(
                    "total_network_indicators",
                    0,
                )
                > 0
                else "info"
            ),
            "evidence": {
                "total_network_indicators": network_intelligence.get(
                    "total_network_indicators",
                    0,
                ),
                "network_flags": network_intelligence.get(
                    "network_flags",
                    {},
                ),
            },
        }
    )


def _add_filesystem_event(
    events: list[dict[str, Any]],
    filesystem_intelligence: dict[str, Any],
) -> None:
    """
    Add filesystem intelligence event.
    """

    if not filesystem_intelligence:
        return

    events.append(
        {
            "stage": "filesystem_intelligence",
            "title": "Runtime filesystem intelligence generated",
            "success": filesystem_intelligence.get("success", False),
            "severity": (
                "medium"
                if filesystem_intelligence.get(
                    "total_filesystem_indicators",
                    0,
                )
                > 0
                else "info"
            ),
            "evidence": {
                "total_filesystem_indicators": filesystem_intelligence.get(
                    "total_filesystem_indicators",
                    0,
                ),
                "filesystem_flags": filesystem_intelligence.get(
                    "filesystem_flags",
                    {},
                ),
            },
        }
    )


def _add_intent_event(
    events: list[dict[str, Any]],
    intent_intelligence: dict[str, Any],
) -> None:
    """
    Add intent intelligence event.
    """

    if not intent_intelligence:
        return

    events.append(
        {
            "stage": "intent_intelligence",
            "title": "Runtime intent intelligence generated",
            "success": intent_intelligence.get("success", False),
            "severity": (
                "medium"
                if intent_intelligence.get(
                    "total_intent_indicators",
                    0,
                )
                > 0
                else "info"
            ),
            "evidence": {
                "total_intent_indicators": intent_intelligence.get(
                    "total_intent_indicators",
                    0,
                ),
                "intent_flags": intent_intelligence.get(
                    "intent_flags",
                    {},
                ),
            },
        }
    )


def _add_persistence_event(
    events: list[dict[str, Any]],
    persistence_intelligence: dict[str, Any],
) -> None:
    """
    Add persistence intelligence event.
    """

    if not persistence_intelligence:
        return

    confidence = persistence_intelligence.get(
        "overall_confidence",
        "none",
    )

    events.append(
        {
            "stage": "persistence_intelligence",
            "title": "Persistence intelligence generated",
            "success": persistence_intelligence.get("success", False),
            "severity": (
                "high"
                if confidence == "high"
                else "medium"
                if confidence == "medium"
                else "info"
            ),
            "evidence": {
                "persistence_indicator_count": (
                    persistence_intelligence.get(
                        "persistence_indicator_count",
                        0,
                    )
                ),
                "overall_confidence": confidence,
                "persistence_flags": persistence_intelligence.get(
                    "persistence_flags",
                    {},
                ),
            },
        }
    )


def _add_report_event(
    events: list[dict[str, Any]],
    final_report: dict[str, Any],
) -> None:
    """
    Add final report generation event.
    """

    if not final_report:
        return

    events.append(
        {
            "stage": "final_report",
            "title": "Final report generated",
            "success": final_report.get("success", False),
            "severity": "info",
            "evidence": {
                "report_path": final_report.get("report_path", ""),
                "report_filename": final_report.get(
                    "report_filename",
                    "",
                ),
            },
        }
    )


def _build_timeline_summary(
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build summary counts for timeline events.
    """

    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for event in events:
        severity = event.get("severity", "info")

        if severity not in summary:
            severity = "info"

        summary[severity] += 1

    return summary