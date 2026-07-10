"""
AndroAI Sandbox - Report Validator

This module validates final analysis reports to make sure the
expected evidence sections are present and usable.

Phase 49 scope:
- Validate required final report sections
- Detect missing or empty sections
- Produce report quality status
- Keep validation evidence-based and deterministic
"""

from typing import Any


REQUIRED_REPORT_SECTIONS = [
    "report_metadata",
    "apk",
    "static_analysis",
    "dynamic_analysis",
    "behavior_analysis",
    "dynamic_mitre_attack",
    "evidence_correlation",
    "iocs",
    "dynamic_risk",
    "combined_risk",
    "ai_analyst_report",
]


def validate_final_report(
    final_report: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate final report completeness and quality.
    """

    missing_sections = []
    empty_sections = []

    for section in REQUIRED_REPORT_SECTIONS:
        if section not in final_report:
            missing_sections.append(section)
            continue

        if _is_empty(final_report.get(section)):
            empty_sections.append(section)

    quality_checks = {
        "has_apk_metadata": bool(final_report.get("apk")),
        "has_static_summary": bool(
            final_report.get("static_analysis", {}).get("summary"),
        ),
        "has_dynamic_summary": bool(
            final_report.get("dynamic_analysis", {}).get(
                "behavior_summary",
            ),
        ),
        "has_behavior_analysis": bool(
            final_report.get("behavior_analysis"),
        ),
        "has_iocs": bool(final_report.get("iocs")),
        "has_combined_risk": bool(final_report.get("combined_risk")),
        "has_ai_report": bool(final_report.get("ai_analyst_report")),
    }

    passed_quality_checks = sum(
        1 for check_passed in quality_checks.values() if check_passed
    )

    validation_passed = (
        not missing_sections
        and passed_quality_checks >= len(quality_checks) - 1
    )

    return {
        "success": True,
        "validation_passed": validation_passed,
        "missing_sections": missing_sections,
        "empty_sections": empty_sections,
        "quality_checks": quality_checks,
        "passed_quality_check_count": passed_quality_checks,
        "total_quality_check_count": len(quality_checks),
        "report_quality_level": _quality_level(
            missing_sections=missing_sections,
            passed_quality_checks=passed_quality_checks,
            total_quality_checks=len(quality_checks),
        ),
        "message": "Final report validation completed.",
    }


def _is_empty(value: Any) -> bool:
    """
    Determine whether a report section is empty.
    """

    if value is None:
        return True

    if isinstance(value, (list, dict, str)):
        return len(value) == 0

    return False


def _quality_level(
    missing_sections: list[str],
    passed_quality_checks: int,
    total_quality_checks: int,
) -> str:
    """
    Convert validation results into a simple quality level.
    """

    if missing_sections:
        return "incomplete"

    if passed_quality_checks == total_quality_checks:
        return "complete"

    if passed_quality_checks >= total_quality_checks - 1:
        return "mostly_complete"

    return "needs_review"