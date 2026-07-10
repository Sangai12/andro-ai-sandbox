"""
AndroAI Sandbox - Report Sanitizer

This module reduces noisy or oversized runtime evidence before
returning API responses or embedding data into analyst-facing reports.

Phase 48 scope:
- Keep useful behavior summaries
- Remove large raw command outputs from API responses
- Preserve artifact file paths for raw evidence
- Limit long evidence lists
"""

from copy import deepcopy
from typing import Any


def sanitize_dynamic_workflow(
    workflow: dict[str, Any],
) -> dict[str, Any]:
    """
    Return a cleaned copy of the dynamic workflow.
    """

    sanitized_workflow = deepcopy(workflow)

    behavior_snapshot = sanitized_workflow.get("behavior_snapshot", {})

    if behavior_snapshot:
        _sanitize_behavior_snapshot(behavior_snapshot)

    runtime_analysis = sanitized_workflow.get("runtime_analysis", {})

    if runtime_analysis:
        _limit_runtime_analysis(runtime_analysis)

    final_report = sanitized_workflow.get("final_report", {})

    if final_report:
        _sanitize_final_report(final_report)

    return sanitized_workflow


def _sanitize_behavior_snapshot(
    behavior_snapshot: dict[str, Any],
) -> None:
    """
    Remove large raw ADB command outputs from behavior snapshot.
    """

    snapshot = behavior_snapshot.get("snapshot", {})

    if not snapshot:
        return

    raw_status = snapshot.get("raw_command_status", {})

    for command_result in raw_status.values():
        if isinstance(command_result, dict):
            command_result.pop("stdout", None)

    snapshot["raw_command_status"] = raw_status


def _limit_runtime_analysis(
    runtime_analysis: dict[str, Any],
    limit: int = 15,
) -> None:
    """
    Limit long runtime evidence lists.
    """

    list_keys = [
        "crashes",
        "exceptions",
        "permission_denials",
        "network_indicators",
        "webview_indicators",
        "security_indicators",
        "warnings",
        "errors",
    ]

    for key in list_keys:
        values = runtime_analysis.get(key)

        if isinstance(values, list):
            runtime_analysis[key] = values[:limit]


def _sanitize_final_report(
    final_report_result: dict[str, Any],
) -> None:
    """
    Limit large nested final report sections.
    """

    report = final_report_result.get("report", {})

    if not report:
        return

    dynamic_analysis = report.get("dynamic_analysis", {})

    if dynamic_analysis:
        _limit_runtime_analysis(dynamic_analysis)

    behavior_analysis = report.get("behavior_analysis", {})

    if behavior_analysis:
        _limit_behavior_analysis(behavior_analysis)

    iocs = report.get("iocs", {})

    if iocs:
        _limit_iocs(iocs)

    dynamic_mitre_attack = report.get("dynamic_mitre_attack", [])

    if isinstance(dynamic_mitre_attack, list):
        for technique in dynamic_mitre_attack:
            evidence = technique.get("evidence")
            if isinstance(evidence, list):
                technique["evidence"] = evidence[:5]


def _limit_behavior_analysis(
    behavior_analysis: dict[str, Any],
    limit: int = 15,
) -> None:
    """
    Limit long behavior analysis evidence lists.
    """

    list_keys = [
        "processes",
        "foreground_activity",
        "running_services",
    ]

    for key in list_keys:
        values = behavior_analysis.get(key)

        if isinstance(values, list):
            behavior_analysis[key] = values[:limit]


def _limit_iocs(
    iocs: dict[str, Any],
    limit: int = 30,
) -> None:
    """
    Limit long IOC lists while preserving counts.
    """

    list_keys = [
        "urls",
        "domains",
        "ip_addresses",
        "email_addresses",
        "permissions",
        "native_libraries",
        "dynamic_network_indicators",
        "dynamic_security_indicators",
        "classified_iocs",
    ]

    for key in list_keys:
        values = iocs.get(key)

        if isinstance(values, list):
            iocs[key] = values[:limit]