"""
AndroAI Sandbox - Service Intelligence

This module analyzes app-related service evidence collected from
Android runtime behavior snapshots.

Phase 53 scope:
- Parse app service lines from behavior analysis
- Count running services
- Identify foreground/background service clues
- Detect multiple service indicators
- Build analyst-friendly service summaries
"""

from typing import Any


def analyze_service_intelligence(
    behavior_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze running service evidence from behavior analysis output.
    """

    service_lines = behavior_analysis.get("running_services", [])

    parsed_services = [
        service
        for service in (
            _parse_service_line(line)
            for line in service_lines
        )
        if service
    ]

    service_names = [
        service.get("name", "")
        for service in parsed_services
        if service.get("name")
    ]

    unique_service_names = sorted(set(service_names))

    foreground_service_lines = [
        line
        for line in service_lines
        if "foreground" in line.lower()
    ]

    background_service_lines = [
        line
        for line in service_lines
        if "background" in line.lower()
    ]

    return {
        "success": True,
        "package_name": behavior_analysis.get("package_name", ""),
        "service_count": len(parsed_services),
        "unique_service_count": len(unique_service_names),
        "unique_service_names": unique_service_names,
        "foreground_service_indicator_count": len(
            foreground_service_lines,
        ),
        "background_service_indicator_count": len(
            background_service_lines,
        ),
        "services": parsed_services,
        "service_flags": {
            "services_running": len(parsed_services) > 0,
            "multiple_services_detected": len(parsed_services) > 1,
            "foreground_service_indicator_detected": (
                len(foreground_service_lines) > 0
            ),
            "background_service_indicator_detected": (
                len(background_service_lines) > 0
            ),
        },
        "message": "Service intelligence analyzed successfully.",
    }


def _parse_service_line(
    line: str,
) -> dict[str, Any]:
    """
    Parse a service-related dumpsys line into structured evidence.
    """

    stripped_line = line.strip()

    if not stripped_line:
        return {}

    service_name = _extract_service_name(stripped_line)

    return {
        "raw": stripped_line,
        "name": service_name,
        "foreground_indicator": "foreground" in stripped_line.lower(),
        "background_indicator": "background" in stripped_line.lower(),
    }


def _extract_service_name(
    line: str,
) -> str:
    """
    Extract a likely service name from a dumpsys service line.
    """

    if "/" in line:
        parts = line.split()

        for part in parts:
            if "/" in part:
                return part.strip("{}")

    if "ServiceRecord" in line:
        parts = line.split()

        if parts:
            return parts[-1].strip("{}")

    return line[:120]