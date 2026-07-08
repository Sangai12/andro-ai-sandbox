"""
AndroAI Sandbox - Dynamic Runner

This module provides the foundation for Android dynamic analysis.

Phase 29 and Phase 30 scope:
- Verify ADB installation
- Detect connected Android devices or emulators
- Verify emulator readiness
- Install APK files on a target device
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