"""
AndroAI Sandbox - Pipeline Metadata

This module builds traceable metadata for analysis pipeline results.

Phase 51 scope:
- Add pipeline name and version
- Add analysis mode
- Add timestamps
- Add important artifact paths
- Improve API response traceability
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any


PIPELINE_NAME = "AndroAI Sandbox Full Analysis Pipeline"
PIPELINE_VERSION = "0.1.0"


def build_pipeline_metadata(
    apk_path: str | Path,
    package_name: str,
    wait_seconds: int,
    workflow: dict[str, Any],
) -> dict[str, Any]:
    """
    Build metadata for a completed analysis pipeline run.
    """

    logcat_result = workflow.get("collect_logcat", {})
    behavior_snapshot = workflow.get("behavior_snapshot", {})
    final_report = workflow.get("final_report", {})

    return {
        "pipeline_name": PIPELINE_NAME,
        "pipeline_version": PIPELINE_VERSION,
        "analysis_mode": "static_dynamic",
        "package_name": package_name,
        "apk_path": str(apk_path),
        "wait_seconds": wait_seconds,
        "generated_at": datetime.now(UTC).isoformat(),
        "artifacts": {
            "runtime_log": logcat_result.get("log_path", ""),
            "behavior_snapshot": behavior_snapshot.get(
                "snapshot_path",
                "",
            ),
            "final_report": final_report.get("report_path", ""),
            "final_report_filename": final_report.get(
                "report_filename",
                "",
            ),
        },
        "message": "Pipeline metadata generated successfully.",
    }