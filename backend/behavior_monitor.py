"""
AndroAI Sandbox - Behavior Monitor

This module collects runtime behavioral evidence from an Android
device or emulator using ADB.

Phase 45 scope:
- Capture running processes
- Capture package state
- Capture foreground activity
- Capture running services snapshot
- Keep behavior monitoring separate from logcat analysis
"""

from datetime import UTC, datetime
from pathlib import Path
import subprocess
from typing import Any


def collect_behavior_snapshot(
    serial: str,
    package_name: str,
    output_directory: str | Path = "logs",
) -> dict[str, Any]:
    """
    Collect a runtime behavior snapshot from the selected Android device.
    """

    output_path = Path(output_directory)
    output_path.mkdir(exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_package_name = package_name.replace(".", "_")
    snapshot_filename = f"{safe_package_name}_{timestamp}_behavior.json"
    snapshot_path = output_path / snapshot_filename

    processes = _run_adb_shell(
        serial=serial,
        command=["ps", "-A"],
    )

    package_info = _run_adb_shell(
        serial=serial,
        command=["dumpsys", "package", package_name],
    )

    foreground_activity = _run_adb_shell(
        serial=serial,
        command=["dumpsys", "activity", "activities"],
    )

    running_services = _run_adb_shell(
        serial=serial,
        command=["dumpsys", "activity", "services"],
    )

    snapshot = {
        "success": True,
        "serial": serial,
        "package_name": package_name,
        "collected_at": datetime.now(UTC).isoformat(),
        "processes": _filter_process_lines(
            processes.get("stdout", ""),
            package_name,
        ),
        "package_state": _summarize_package_state(
            package_info.get("stdout", ""),
        ),
        "foreground_activity": _extract_foreground_activity(
            foreground_activity.get("stdout", ""),
            package_name,
        ),
        "running_services": _filter_process_lines(
            running_services.get("stdout", ""),
            package_name,
        ),
        "raw_command_status": {
            "processes": processes,
            "package_info": package_info,
            "foreground_activity": {
                "success": foreground_activity.get("success", False),
                "stderr": foreground_activity.get("stderr", ""),
            },
            "running_services": {
                "success": running_services.get("success", False),
                "stderr": running_services.get("stderr", ""),
            },
        },
    }

    snapshot_path.write_text(
        _to_json(snapshot),
        encoding="utf-8",
    )

    return {
        "success": True,
        "snapshot_path": str(snapshot_path),
        "snapshot_filename": snapshot_filename,
        "snapshot": snapshot,
        "message": "Behavior snapshot collected successfully.",
    }


def _run_adb_shell(
    serial: str,
    command: list[str],
) -> dict[str, Any]:
    """
    Run an ADB shell command and return structured output.
    """

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "shell",
            *command,
        ],
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "command": " ".join(command),
        "stdout": result.stdout,
        "stderr": result.stderr.strip(),
        "returncode": result.returncode,
    }


def _filter_process_lines(
    text: str,
    package_name: str,
    limit: int = 50,
) -> list[str]:
    """
    Return lines related to the target package.
    """

    matches = []

    for line in text.splitlines():
        if package_name.lower() in line.lower():
            matches.append(line.strip())

        if len(matches) >= limit:
            break

    return matches


def _summarize_package_state(
    package_text: str,
) -> dict[str, Any]:
    """
    Extract useful package state indicators from dumpsys package output.
    """

    interesting_keywords = [
        "userId=",
        "pkg=",
        "versionName=",
        "versionCode=",
        "firstInstallTime=",
        "lastUpdateTime=",
        "installerPackageName=",
        "enabled=",
        "stopped=",
        "hidden=",
        "suspended=",
    ]

    matched_lines = []

    for line in package_text.splitlines():
        stripped_line = line.strip()

        if any(keyword in stripped_line for keyword in interesting_keywords):
            matched_lines.append(stripped_line)

    return {
        "matched_line_count": len(matched_lines),
        "matched_lines": matched_lines[:80],
    }


def _extract_foreground_activity(
    activity_text: str,
    package_name: str,
) -> dict[str, Any]:
    """
    Extract foreground or resumed activity evidence.
    """

    activity_lines = []

    keywords = [
        "mResumedActivity",
        "topResumedActivity",
        "ResumedActivity",
        package_name,
    ]

    for line in activity_text.splitlines():
        stripped_line = line.strip()

        if any(keyword in stripped_line for keyword in keywords):
            activity_lines.append(stripped_line)

    return {
        "matched_line_count": len(activity_lines),
        "matched_lines": activity_lines[:80],
    }


def _to_json(data: dict[str, Any]) -> str:
    """
    Serialize data to pretty JSON.
    """

    import json

    return json.dumps(
        data,
        indent=2,
    )