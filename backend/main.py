"""
AndroAI Sandbox - Backend Entry Point

This module creates the FastAPI application for the AndroAI Sandbox backend.

Current scope:
- Create the FastAPI app
- Add a root endpoint
- Add a health-check endpoint
- Add dynamic analysis environment status endpoint
- Add APK installation endpoint
- Add APK launch endpoint
- Add runtime logcat collection endpoint
- Add runtime logcat analysis endpoint
- Add automated dynamic analysis endpoint
- Add dynamic behavior snapshot collection
- Add dynamic risk scoring
- Add combined static and dynamic risk scoring
- Add final JSON report generation
- Register the APK upload router
- Register the report download router
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException

from backend.behavior_monitor import collect_behavior_snapshot
from backend.combined_risk_engine import calculate_combined_risk
from backend.dynamic_risk_score import calculate_dynamic_risk_score
from backend.dynamic_runner import (
    check_adb,
    clear_logcat,
    collect_logcat,
    get_connected_devices,
    get_first_ready_device,
    install_apk,
    is_device_ready,
    launch_app,
    wait_for_runtime,
)
from backend.final_report_generator import build_final_analysis_report
from backend.report_handler import router as report_router
from backend.runtime_log_analyzer import analyze_runtime_log
from backend.static_analyzer import extract_apk_metadata
from backend.upload_handler import router as upload_router


UPLOAD_DIRECTORY = Path("uploads")
LOG_DIRECTORY = Path("logs")


app = FastAPI(
    title="AndroAI Sandbox API",
    description="Evidence-Based AI-Powered Android Malware Analysis Sandbox backend.",
    version="0.1.0",
)

app.include_router(upload_router)
app.include_router(report_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AndroAI Sandbox backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "androai-backend",
    }


@app.get("/dynamic/status")
def dynamic_status() -> dict:
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


@app.post("/dynamic/launch/{package_name}")
def dynamic_launch(package_name: str) -> dict:
    device = get_first_ready_device()

    if device is None:
        raise HTTPException(
            status_code=503,
            detail="No ready Android device or emulator found.",
        )

    launch_result = launch_app(
        serial=device["serial"],
        package_name=package_name,
    )

    return {
        "package_name": package_name,
        "device": device,
        "launch_result": launch_result,
    }


@app.post("/dynamic/logcat/{package_name}")
def dynamic_logcat(package_name: str) -> dict:
    """
    Collect recent runtime logcat output from the first ready device.
    """

    device = get_first_ready_device()

    if device is None:
        raise HTTPException(
            status_code=503,
            detail="No ready Android device or emulator found.",
        )

    logcat_result = collect_logcat(
        serial=device["serial"],
        package_name=package_name,
    )

    return {
        "package_name": package_name,
        "device": device,
        "logcat_result": logcat_result,
    }


@app.post("/dynamic/logcat/clear")
def dynamic_clear_logcat() -> dict:
    """
    Clear logcat buffer on the first ready device.
    """

    device = get_first_ready_device()

    if device is None:
        raise HTTPException(
            status_code=503,
            detail="No ready Android device or emulator found.",
        )

    clear_result = clear_logcat(
        serial=device["serial"],
    )

    return {
        "device": device,
        "clear_result": clear_result,
    }


@app.post("/dynamic/logcat/analyze/{log_filename}")
def dynamic_analyze_logcat(log_filename: str) -> dict:
    """
    Analyze a saved runtime logcat file.
    """

    if not log_filename.endswith(".log"):
        raise HTTPException(
            status_code=400,
            detail="Only .log files can be analyzed.",
        )

    log_path = LOG_DIRECTORY / log_filename

    if not log_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Runtime log file not found.",
        )

    analysis_result = analyze_runtime_log(log_path)
    dynamic_risk = calculate_dynamic_risk_score(analysis_result)

    return {
        "log_file": str(log_path),
        "analysis_result": analysis_result,
        "dynamic_risk": dynamic_risk,
    }


@app.post("/dynamic/analyze/{stored_filename}/{package_name}")
def dynamic_analyze(
    stored_filename: str,
    package_name: str,
    wait_seconds: int = 10,
) -> dict:
    """
    Run the automated dynamic analysis workflow.
    """

    if not stored_filename.endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only APK files can be analyzed dynamically.",
        )

    apk_path = UPLOAD_DIRECTORY / stored_filename

    if not apk_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Uploaded APK not found.",
        )

    static_analysis = extract_apk_metadata(apk_path)

    device = get_first_ready_device()

    if device is None:
        raise HTTPException(
            status_code=503,
            detail="No ready Android device or emulator found.",
        )

    clear_result = clear_logcat(
        serial=device["serial"],
    )

    install_result = install_apk(
        apk_path=apk_path,
        serial=device["serial"],
    )

    launch_result = launch_app(
        serial=device["serial"],
        package_name=package_name,
    )

    wait_result = wait_for_runtime(wait_seconds)

    behavior_snapshot = collect_behavior_snapshot(
        serial=device["serial"],
        package_name=package_name,
    )

    logcat_result = collect_logcat(
        serial=device["serial"],
        package_name=package_name,
    )

    runtime_analysis = {}
    dynamic_risk = {}
    combined_risk = {}
    final_report = {}

    if logcat_result.get("success"):
        runtime_analysis = analyze_runtime_log(
            logcat_result["log_path"],
        )

        dynamic_risk = calculate_dynamic_risk_score(runtime_analysis)

        combined_risk = calculate_combined_risk(
            static_analysis=static_analysis,
            dynamic_risk=dynamic_risk,
        )

        final_report = build_final_analysis_report(
            apk_path=str(apk_path),
            package_name=package_name,
            static_analysis=static_analysis,
            runtime_analysis=runtime_analysis,
            dynamic_risk=dynamic_risk,
            combined_risk=combined_risk,
        )

    return {
        "apk": str(apk_path),
        "package_name": package_name,
        "device": device,
        "static_analysis": {
            "summary": static_analysis.get("summary", {}),
            "finding_count": static_analysis.get("finding_count", 0),
        },
        "workflow": {
            "clear_logcat": clear_result,
            "install": install_result,
            "launch": launch_result,
            "wait": wait_result,
            "behavior_snapshot": behavior_snapshot,
            "collect_logcat": logcat_result,
            "runtime_analysis": runtime_analysis,
            "dynamic_risk": dynamic_risk,
            "combined_risk": combined_risk,
            "final_report": final_report,
        },
        "success": all(
            [
                clear_result.get("success"),
                install_result.get("success"),
                launch_result.get("success"),
                wait_result.get("success"),
                behavior_snapshot.get("success"),
                logcat_result.get("success"),
            ]
        ),
    }