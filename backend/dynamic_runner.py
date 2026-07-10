"""
AndroAI Sandbox - Dynamic Runner

This module provides the foundation for Android dynamic analysis.

Current scope:
- Verify ADB installation
- Detect connected Android devices or emulators
- Verify emulator readiness
- Install APK files on a target device
- Launch installed APK packages
- Resolve active application process IDs
- Collect package-filtered runtime logcat evidence
- Wait during runtime observation
- Support automated dynamic analysis
"""

from datetime import UTC, datetime
from pathlib import Path
import subprocess
import time
from typing import Any


def check_adb() -> bool:
    """
    Verify that Android Debug Bridge (ADB) is available.
    """

    try:
        subprocess.run(
            ["adb", "version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        return False


def get_connected_devices() -> list[dict[str, Any]]:
    """
    Return all connected Android devices and emulators.
    """

    result = subprocess.run(
        ["adb", "devices"],
        capture_output=True,
        text=True,
        check=True,
    )

    devices = []

    for line in result.stdout.splitlines()[1:]:
        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        devices.append(
            {
                "serial": parts[0],
                "state": parts[1],
            }
        )

    return devices


def is_device_ready(serial: str) -> bool:
    """
    Check whether an Android device is fully booted.
    """

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "getprop",
            "sys.boot_completed",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip() == "1"


def install_apk(
    apk_path: str | Path,
    serial: str,
) -> dict[str, Any]:
    """
    Install an APK on the selected Android device or emulator.
    """

    apk_file = Path(apk_path)

    if not apk_file.exists():
        return {
            "success": False,
            "apk_path": str(apk_file),
            "serial": serial,
            "message": "APK file not found.",
            "stdout": "",
            "stderr": "",
        }

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "install",
            "-r",
            str(apk_file),
        ],
        capture_output=True,
        text=True,
    )

    success = result.returncode == 0

    return {
        "success": success,
        "apk_path": str(apk_file),
        "serial": serial,
        "message": (
            "APK installed successfully."
            if success
            else "APK installation failed."
        ),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def get_first_ready_device() -> dict[str, Any] | None:
    """
    Return the first connected and fully booted Android device.
    """

    devices = get_connected_devices()

    for device in devices:
        serial = device["serial"]

        if device["state"] != "device":
            continue

        if is_device_ready(serial):
            return {
                "serial": serial,
                "state": device["state"],
                "ready": True,
            }

    return None


def get_launch_activity(
    serial: str,
    package_name: str,
) -> dict[str, Any]:
    """
    Resolve the launchable activity for an installed Android package.
    """

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            package_name,
        ],
        capture_output=True,
        text=True,
    )

    output_lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    launch_activity = output_lines[-1] if output_lines else ""

    success = (
        result.returncode == 0
        and bool(launch_activity)
        and "/" in launch_activity
    )

    return {
        "success": success,
        "package_name": package_name,
        "launch_activity": launch_activity,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def launch_app(
    serial: str,
    package_name: str,
) -> dict[str, Any]:
    """
    Launch an installed Android application by package name.
    """

    launch_activity_result = get_launch_activity(
        serial=serial,
        package_name=package_name,
    )

    if not launch_activity_result["success"]:
        return {
            "success": False,
            "package_name": package_name,
            "serial": serial,
            "message": "Launch activity could not be resolved.",
            "launch_activity": "",
            "stdout": launch_activity_result["stdout"],
            "stderr": launch_activity_result["stderr"],
        }

    launch_activity = launch_activity_result["launch_activity"]

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "am",
            "start",
            "-n",
            launch_activity,
        ],
        capture_output=True,
        text=True,
    )

    success = result.returncode == 0

    return {
        "success": success,
        "package_name": package_name,
        "serial": serial,
        "message": (
            "Application launched successfully."
            if success
            else "Application launch failed."
        ),
        "launch_activity": launch_activity,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def clear_logcat(serial: str) -> dict[str, Any]:
    """
    Clear the device logcat buffer.
    """

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "logcat",
            "-c",
        ],
        capture_output=True,
        text=True,
    )

    success = result.returncode == 0

    return {
        "success": success,
        "serial": serial,
        "message": (
            "Logcat buffer cleared."
            if success
            else "Failed to clear logcat buffer."
        ),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def get_package_pids(
    serial: str,
    package_name: str,
) -> dict[str, Any]:
    """
    Resolve all active process IDs associated with an Android package.
    """

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "pidof",
            package_name,
        ],
        capture_output=True,
        text=True,
    )

    pids = [
        value
        for value in result.stdout.strip().split()
        if value.isdigit()
    ]

    return {
        "success": result.returncode == 0 and bool(pids),
        "serial": serial,
        "package_name": package_name,
        "pids": pids,
        "pid_count": len(pids),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "message": (
            "Package process IDs resolved successfully."
            if pids
            else "No active package process IDs were found."
        ),
    }


def collect_logcat(
    serial: str,
    package_name: str,
    output_directory: str | Path = "logs",
    line_count: int = 2000,
) -> dict[str, Any]:
    """
    Collect recent logcat output filtered to the target package processes.

    The complete device buffer is read first. Evidence is then restricted
    to active process IDs belonging to the target package. If active PIDs
    cannot be resolved, package-name matching is used as a fallback.
    """

    log_directory = Path(output_directory)
    log_directory.mkdir(exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_package_name = package_name.replace(".", "_")
    log_filename = f"{safe_package_name}_{timestamp}.log"
    log_path = log_directory / log_filename

    package_pid_result = get_package_pids(
        serial=serial,
        package_name=package_name,
    )

    result = subprocess.run(
        [
            "adb",
            "-s",
            serial,
            "logcat",
            "-d",
            "-v",
            "threadtime",
            "-t",
            str(line_count),
        ],
        capture_output=True,
        text=True,
    )

    success = result.returncode == 0

    raw_lines = result.stdout.splitlines() if success else []
    package_pids = set(package_pid_result.get("pids", []))

    if package_pids:
        filtered_lines = _filter_logcat_lines_by_pid(
            lines=raw_lines,
            package_pids=package_pids,
        )
        filter_mode = "package_pids"
    else:
        filtered_lines = _filter_logcat_lines_by_package(
            lines=raw_lines,
            package_name=package_name,
        )
        filter_mode = "package_name_fallback"

    filtered_text = "\n".join(filtered_lines)

    if filtered_text:
        filtered_text += "\n"

    if success:
        log_path.write_text(
            filtered_text,
            encoding="utf-8",
        )

    return {
        "success": success,
        "serial": serial,
        "package_name": package_name,
        "log_path": str(log_path) if success else "",
        "line_count_requested": line_count,
        "raw_line_count": len(raw_lines),
        "filtered_line_count": len(filtered_lines),
        "filter_mode": filter_mode,
        "package_pids": sorted(package_pids, key=int),
        "package_pid_count": len(package_pids),
        "pid_resolution": package_pid_result,
        "message": (
            "Package-filtered logcat collected successfully."
            if success
            else "Failed to collect logcat."
        ),
        "stderr": result.stderr.strip(),
    }


def _filter_logcat_lines_by_pid(
    lines: list[str],
    package_pids: set[str],
) -> list[str]:
    """
    Keep logcat lines whose process ID belongs to the target package.

    Threadtime logcat lines normally use this structure:

    date time PID TID priority tag: message
    """

    filtered_lines = []
    previous_line_matched = False

    for line in lines:
        parts = line.split()

        current_line_matches = (
            len(parts) >= 3
            and parts[2] in package_pids
        )

        continuation_line = (
            previous_line_matched
            and (
                line.startswith(" ")
                or line.startswith("\t")
                or line.lstrip().startswith("at ")
                or line.lstrip().startswith("Caused by:")
            )
        )

        if current_line_matches or continuation_line:
            filtered_lines.append(line)

        previous_line_matched = current_line_matches

    return filtered_lines


def _filter_logcat_lines_by_package(
    lines: list[str],
    package_name: str,
) -> list[str]:
    """
    Use package-name matching when active process IDs are unavailable.
    """

    package_name_lower = package_name.lower()
    filtered_lines = []
    previous_line_matched = False

    for line in lines:
        current_line_matches = package_name_lower in line.lower()

        continuation_line = (
            previous_line_matched
            and (
                line.startswith(" ")
                or line.startswith("\t")
                or line.lstrip().startswith("at ")
                or line.lstrip().startswith("Caused by:")
            )
        )

        if current_line_matches or continuation_line:
            filtered_lines.append(line)

        previous_line_matched = current_line_matches

    return filtered_lines


def wait_for_runtime(seconds: int = 10) -> dict[str, Any]:
    """
    Wait while the launched application runs.
    """

    time.sleep(seconds)

    return {
        "success": True,
        "wait_seconds": seconds,
        "message": f"Runtime observation waited for {seconds} seconds.",
    }