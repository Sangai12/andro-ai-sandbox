"""
AndroAI Sandbox - Dynamic Runner

This module provides the foundation for Android dynamic analysis.

Phase 29.1 scope:
- Verify ADB installation
- Detect connected Android devices or emulators
- Verify emulator readiness
- Prepare for future dynamic analysis
"""

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