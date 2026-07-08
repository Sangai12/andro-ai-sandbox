"""
AndroAI Sandbox - Backend Entry Point

This module creates the FastAPI application for the AndroAI Sandbox backend.

Current scope:
- Create the FastAPI app
- Add a root endpoint
- Add a health-check endpoint
- Add dynamic analysis environment status endpoint
- Register the APK upload router
- Register the report download router
"""

from fastapi import FastAPI

from backend.dynamic_runner import (
    check_adb,
    get_connected_devices,
    is_device_ready,
)
from backend.report_handler import router as report_router
from backend.upload_handler import router as upload_router


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