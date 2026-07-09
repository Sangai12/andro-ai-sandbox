"""
AndroAI Sandbox - Behavior Analyzer

This module converts raw behavior monitor snapshots into
clean analyst-friendly runtime behavior summaries.

Phase 46 scope:
- Count app-related processes
- Summarize foreground activity
- Summarize running services
- Summarize package state
- Detect whether app appears active at runtime
"""

from typing import Any


def analyze_behavior_snapshot(
    behavior_snapshot_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze behavior snapshot output and produce a clean summary.
    """

    snapshot = behavior_snapshot_result.get("snapshot", {})

    if not snapshot:
        return {
            "success": False,
            "message": "No behavior snapshot available.",
        }

    processes = snapshot.get("processes", [])
    foreground_activity = snapshot.get("foreground_activity", {})
    running_services = snapshot.get("running_services", [])
    package_state = snapshot.get("package_state", {})

    process_count = len(processes)
    running_service_count = len(running_services)

    foreground_lines = foreground_activity.get("matched_lines", [])
    foreground_match_count = foreground_activity.get(
        "matched_line_count",
        0,
    )

    package_lines = package_state.get("matched_lines", [])

    app_active = process_count > 0 or foreground_match_count > 0

    package_flags = _extract_package_flags(package_lines)

    return {
        "success": True,
        "package_name": snapshot.get("package_name", ""),
        "serial": snapshot.get("serial", ""),
        "collected_at": snapshot.get("collected_at", ""),
        "app_active": app_active,
        "process_count": process_count,
        "processes": processes,
        "foreground_activity_detected": foreground_match_count > 0,
        "foreground_activity_count": foreground_match_count,
        "foreground_activity": foreground_lines[:20],
        "running_service_count": running_service_count,
        "running_services": running_services[:30],
        "package_state": package_flags,
        "behavior_flags": {
            "app_process_running": process_count > 0,
            "foreground_activity_detected": foreground_match_count > 0,
            "services_running": running_service_count > 0,
            "package_installed": package_flags.get("installed", False),
            "package_stopped": package_flags.get("stopped", False),
            "package_hidden": package_flags.get("hidden", False),
            "package_suspended": package_flags.get("suspended", False),
        },
        "message": "Behavior snapshot analyzed successfully.",
    }


def _extract_package_flags(
    package_lines: list[str],
) -> dict[str, Any]:
    """
    Extract package state flags from summarized package lines.
    """

    flags = {
        "installed": False,
        "hidden": False,
        "suspended": False,
        "stopped": False,
        "enabled": "",
        "version_name": "",
        "version_code": "",
        "first_install_time": "",
        "last_update_time": "",
        "installer_package_name": "",
    }

    for line in package_lines:
        if "versionName=" in line:
            flags["version_name"] = _value_after_key(
                line,
                "versionName=",
            )

        if "versionCode=" in line:
            flags["version_code"] = _value_after_key(
                line,
                "versionCode=",
            )

        if "firstInstallTime=" in line:
            flags["first_install_time"] = _value_after_key(
                line,
                "firstInstallTime=",
            )

        if "lastUpdateTime=" in line:
            flags["last_update_time"] = _value_after_key(
                line,
                "lastUpdateTime=",
            )

        if "installerPackageName=" in line:
            flags["installer_package_name"] = _value_after_key(
                line,
                "installerPackageName=",
            )

        if "installed=true" in line:
            flags["installed"] = True

        if "hidden=true" in line:
            flags["hidden"] = True

        if "suspended=true" in line:
            flags["suspended"] = True

        if "stopped=true" in line:
            flags["stopped"] = True

        if "enabled=" in line:
            flags["enabled"] = _value_after_key(
                line,
                "enabled=",
            )

    return flags


def _value_after_key(
    text: str,
    key: str,
) -> str:
    """
    Extract value after a key until the next space.
    """

    if key not in text:
        return ""

    value = text.split(key, 1)[1].strip()

    if " " in value:
        return value.split(" ", 1)[0]

    return value