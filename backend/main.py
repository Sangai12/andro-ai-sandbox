"""
AndroAI Sandbox - Backend Entry Point

This module creates the FastAPI application for the AndroAI Sandbox backend.

Current scope:
- Create the FastAPI app
- Add a root endpoint
- Add a health-check endpoint
- Add dynamic analysis environment status endpoint
- Add APK installation endpoint
- Register the APK upload router
- Register the report download router
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException

from backend.dynamic_runner import (
    check_adb,
    get_connected_devices,
    get_first_ready_device,
    install_apk,
    is_device_ready,
)
from backend.report_handler import router as report_router
from backend.upload_handler import router as upload_router


UPLOAD_DIRECTORY = Path("uploads")


app = FastAPI(
    title="AndroAI Sandbox API",
    description="Evidence-Based AI-Powered Android Malware Analysis Sandbox backend.",
    version="0.1.0",
)

# Register API routers
app.include_router(upload_router)
app.include_router(report_router)


@app.get("/")
def root() -> dict[str, str]:
    """
    Root endpoint used to verify that the backend server is running.
    """
    return {"message": "AndroAI Sandbox backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    """
    Health-check endpoint used for testing and monitoring.
    """
    return {
        "status": "ok",
        "service": "androai-backend",
    }


@app.get("/dynamic/status")
def dynamic_status() -> dict:
    """
    Return dynamic analysis environment status.
    """

    adb_available = check_adb()

    if not adb_available:
        return {
            "adb_available": False,
            "devices": [],
            "ready": False,
            "message": "ADB is not available.",
        }

    devices = get_connected_devices()

    device_status = []

    for device in devices:
        serial = device["serial"]
        state = device["state"]

        ready = False

        if state == "device":
            ready = is_device_ready(serial)

        device_status.append(
            {
                "serial": serial,
                "state": state,
                "ready": ready,
            }
        )

    return {
        "adb_available": adb_available,
        "devices": device_status,
        "ready": any(device["ready"] for device in device_status),
        "message": "Dynamic analysis environment status checked.",
    }


@app.post("/dynamic/install/{stored_filename}")
def dynamic_install(stored_filename: str) -> dict:
    """
    Install a previously uploaded APK on the first ready Android device.
    """

    if not stored_filename.endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only APK files can be installed.",
        )

    apk_path = UPLOAD_DIRECTORY / stored_filename

    if not apk_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Uploaded APK not found.",
        )

    device = get_first_ready_device()

    if device is None:
        raise HTTPException(
            status_code=503,
            detail="No ready Android device or emulator found.",
        )

    install_result = install_apk(
        apk_path=apk_path,
        serial=device["serial"],
    )

    return {
        "apk": str(apk_path),
        "device": device,
        "install_result": install_result,
    }