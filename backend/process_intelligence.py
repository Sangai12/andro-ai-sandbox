"""
AndroAI Sandbox - Process Intelligence

This module analyzes app-related process evidence collected from
Android runtime behavior snapshots.

Phase 52 scope:
- Parse app process lines from behavior snapshots
- Extract basic process fields
- Count process instances
- Detect primary and child/secondary processes
- Build analyst-friendly process summaries
"""

from typing import Any


def analyze_process_intelligence(
    behavior_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze process evidence from behavior analysis output.
    """

    process_lines = behavior_analysis.get("processes", [])

    parsed_processes = [
        process
        for process in (
            _parse_process_line(line)
            for line in process_lines
        )
        if process
    ]

    process_names = [
        process.get("name", "")
        for process in parsed_processes
        if process.get("name")
    ]

    unique_process_names = sorted(set(process_names))

    primary_process = _select_primary_process(
        parsed_processes=parsed_processes,
        package_name=behavior_analysis.get("package_name", ""),
    )

    child_processes = [
        process
        for process in parsed_processes
        if process.get("name") != primary_process.get("name", "")
    ]

    return {
        "success": True,
        "package_name": behavior_analysis.get("package_name", ""),
        "process_count": len(parsed_processes),
        "unique_process_count": len(unique_process_names),
        "unique_process_names": unique_process_names,
        "primary_process": primary_process,
        "child_process_count": len(child_processes),
        "child_processes": child_processes,
        "processes": parsed_processes,
        "process_flags": {
            "app_process_running": len(parsed_processes) > 0,
            "multiple_processes_detected": len(parsed_processes) > 1,
            "child_processes_detected": len(child_processes) > 0,
        },
        "message": "Process intelligence analyzed successfully.",
    }


def _parse_process_line(
    line: str,
) -> dict[str, Any]:
    """
    Parse a single Android ps output line.
    """

    parts = line.split()

    if len(parts) < 2:
        return {}

    user = parts[0]
    pid = parts[1]
    process_name = parts[-1]

    parsed = {
        "raw": line,
        "user": user,
        "pid": pid,
        "name": process_name,
    }

    if len(parts) >= 3:
        parsed["ppid"] = parts[2]

    if len(parts) >= 8:
        parsed["state"] = parts[-2]

    return parsed


def _select_primary_process(
    parsed_processes: list[dict[str, Any]],
    package_name: str,
) -> dict[str, Any]:
    """
    Select the primary app process when possible.
    """

    for process in parsed_processes:
        if process.get("name") == package_name:
            return process

    if parsed_processes:
        return parsed_processes[0]

    return {}