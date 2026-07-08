"""
AndroAI Sandbox - Dynamic Runner

This module provides the foundation for Android dynamic analysis.

Phase 29, Phase 30, and Phase 31 scope:
- Verify ADB installation
- Detect connected Android devices or emulators
- Verify emulator readiness
- Install APK files on a target device
- Launch installed APK packages
- Prepare for future dynamic analysis
"""

from pathlib import Path
import subprocess
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
        and launch_activity
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