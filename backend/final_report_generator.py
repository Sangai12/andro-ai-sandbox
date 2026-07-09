"""
AndroAI Sandbox - Final Report Generator

This module builds and saves a unified final analysis report.

Phase 38, Phase 41, and Phase 42 scope:
- Combine static summary
- Combine dynamic behavior analysis
- Combine dynamic risk score
- Combine overall risk assessment
- Generate IOC summary
- Generate final AI-style analyst report
- Save final report as JSON evidence
"""

from datetime import UTC, datetime
from pathlib import Path
import json
from typing import Any

from backend.final_ai_report_generator import generate_final_ai_report
from backend.ioc_extractor import extract_iocs_from_report


def build_final_analysis_report(
    apk_path: str,
    package_name: str,
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
    dynamic_risk: dict[str, Any],
    combined_risk: dict[str, Any],
    output_directory: str | Path = "reports",
) -> dict[str, Any]:
    """
    Build and save a unified final analysis report.
    """

    report_directory = Path(output_directory)
    report_directory.mkdir(exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_package_name = package_name.replace(".", "_")
    report_filename = f"{safe_package_name}_{timestamp}_final.json"
    report_path = report_directory / report_filename

    iocs = extract_iocs_from_report(
        static_analysis=static_analysis,
        runtime_analysis=runtime_analysis,
    )

    final_report = {
        "report_metadata": {
            "report_type": "final_static_dynamic_analysis",
            "analyzer_name": "AndroAI Sandbox",
            "analyzer_version": "0.1.0",
            "generated_at": datetime.now(UTC).isoformat(),
        },
        "apk": {
            "apk_path": apk_path,
            "package_name": package_name,
        },
        "static_analysis": {
            "summary": static_analysis.get("summary", {}),
            "finding_count": static_analysis.get("finding_count", 0),
            "mitre_attack_count": static_analysis.get(
                "mitre_attack_count",
                0,
            ),
        },
        "dynamic_analysis": {
            "behavior_summary": runtime_analysis.get(
                "behavior_summary",
                {},
            ),
            "crash_count": runtime_analysis.get("crash_count", 0),
            "exception_count": runtime_analysis.get("exception_count", 0),
            "permission_denial_count": runtime_analysis.get(
                "permission_denial_count",
                0,
            ),
            "network_indicator_count": runtime_analysis.get(
                "network_indicator_count",
                0,
            ),
            "webview_indicator_count": runtime_analysis.get(
                "webview_indicator_count",
                0,
            ),
            "security_indicator_count": runtime_analysis.get(
                "security_indicator_count",
                0,
            ),
            "warning_count": runtime_analysis.get("warning_count", 0),
            "error_count": runtime_analysis.get("error_count", 0),
            "log_path": runtime_analysis.get("log_path", ""),
        },
        "iocs": iocs,
        "dynamic_risk": dynamic_risk,
        "combined_risk": combined_risk,
        "disclaimer": (
            "This report is evidence-based. Findings identify behaviors "
            "and indicators requiring analyst review. They do not prove "
            "malicious behavior by themselves."
        ),
    }

    final_report["ai_analyst_report"] = generate_final_ai_report(
        final_report,
    )

    report_path.write_text(
        json.dumps(
            final_report,
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "success": True,
        "report_path": str(report_path),
        "report_filename": report_filename,
        "report": final_report,
        "message": "Final analysis report generated successfully.",
    }