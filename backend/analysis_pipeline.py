"""
AndroAI Sandbox - Analysis Pipeline

This module orchestrates the full automated analysis workflow.

Phase 50, Phase 51, Phase 52, and Phase 53 scope:
- Keep FastAPI route logic small
- Run static analysis
- Run dynamic install, launch, wait, logcat, and behavior monitoring
- Analyze runtime process intelligence
- Analyze runtime service intelligence
- Calculate dynamic and combined risk
- Generate final report
- Add pipeline metadata
- Sanitize API workflow response
"""

from pathlib import Path
from typing import Any

from fastapi import HTTPException

from backend.behavior_analyzer import analyze_behavior_snapshot
from backend.behavior_monitor import collect_behavior_snapshot
from backend.combined_risk_engine import calculate_combined_risk
from backend.dynamic_risk_score import calculate_dynamic_risk_score
from backend.dynamic_runner import (
    clear_logcat,
    collect_logcat,
    get_first_ready_device,
    install_apk,
    launch_app,
    wait_for_runtime,
)
from backend.final_report_generator import build_final_analysis_report
from backend.pipeline_metadata import build_pipeline_metadata
from backend.process_intelligence import analyze_process_intelligence
from backend.report_sanitizer import sanitize_dynamic_workflow
from backend.runtime_log_analyzer import analyze_runtime_log
from backend.service_intelligence import analyze_service_intelligence
from backend.static_analyzer import extract_apk_metadata


UPLOAD_DIRECTORY = Path("uploads")


def run_full_dynamic_analysis_pipeline(
    stored_filename: str,
    package_name: str,
    wait_seconds: int = 10,
) -> dict[str, Any]:
    """
    Run the full static + dynamic analysis pipeline.
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

    behavior_analysis = analyze_behavior_snapshot(
        behavior_snapshot,
    )

    process_intelligence = analyze_process_intelligence(
        behavior_analysis,
    )

    service_intelligence = analyze_service_intelligence(
        behavior_analysis,
    )

    logcat_result = collect_logcat(
        serial=device["serial"],
        package_name=package_name,
    )

    runtime_analysis: dict[str, Any] = {}
    dynamic_risk: dict[str, Any] = {}
    combined_risk: dict[str, Any] = {}
    final_report: dict[str, Any] = {}

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
            behavior_analysis=behavior_analysis,
            dynamic_risk=dynamic_risk,
            combined_risk=combined_risk,
        )

    workflow = {
        "clear_logcat": clear_result,
        "install": install_result,
        "launch": launch_result,
        "wait": wait_result,
        "behavior_snapshot": behavior_snapshot,
        "behavior_analysis": behavior_analysis,
        "process_intelligence": process_intelligence,
        "service_intelligence": service_intelligence,
        "collect_logcat": logcat_result,
        "runtime_analysis": runtime_analysis,
        "dynamic_risk": dynamic_risk,
        "combined_risk": combined_risk,
        "final_report": final_report,
    }

    metadata = build_pipeline_metadata(
        apk_path=apk_path,
        package_name=package_name,
        wait_seconds=wait_seconds,
        workflow=workflow,
    )

    sanitized_workflow = sanitize_dynamic_workflow(workflow)

    return {
        "pipeline_metadata": metadata,
        "apk": str(apk_path),
        "package_name": package_name,
        "device": device,
        "static_analysis": {
            "summary": static_analysis.get("summary", {}),
            "finding_count": static_analysis.get("finding_count", 0),
        },
        "workflow": sanitized_workflow,
        "success": all(
            [
                clear_result.get("success"),
                install_result.get("success"),
                launch_result.get("success"),
                wait_result.get("success"),
                behavior_snapshot.get("success"),
                behavior_analysis.get("success"),
                process_intelligence.get("success"),
                service_intelligence.get("success"),
                logcat_result.get("success"),
            ]
        ),
    }