"""
AndroAI Sandbox - Evidence Correlator

This module correlates static, dynamic, and behavior evidence
to produce analyst-friendly confidence indicators.

Phase 47 scope:
- Correlate static and dynamic evidence
- Identify reinforced findings
- Produce confidence levels
- Keep conclusions evidence-based
"""

from typing import Any


def correlate_evidence(
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
    behavior_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Correlate static, dynamic, and behavior analysis evidence.
    """

    correlations = []

    _add_network_correlation(
        correlations=correlations,
        static_analysis=static_analysis,
        runtime_analysis=runtime_analysis,
    )

    _add_permission_correlation(
        correlations=correlations,
        static_analysis=static_analysis,
        runtime_analysis=runtime_analysis,
    )

    _add_runtime_activity_correlation(
        correlations=correlations,
        behavior_analysis=behavior_analysis,
        runtime_analysis=runtime_analysis,
    )

    _add_service_correlation(
        correlations=correlations,
        static_analysis=static_analysis,
        behavior_analysis=behavior_analysis,
    )

    confidence_summary = _build_confidence_summary(correlations)

    return {
        "success": True,
        "correlations": correlations,
        "correlation_count": len(correlations),
        "confidence_summary": confidence_summary,
        "message": "Evidence correlation completed successfully.",
    }


def _add_network_correlation(
    correlations: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
) -> None:
    """
    Correlate static network indicators with runtime network activity.
    """

    evidence = static_analysis.get("evidence", {})
    static_network_count = (
        len(evidence.get("urls", []))
        + len(evidence.get("domains", []))
        + len(evidence.get("ip_addresses", []))
    )

    runtime_network_count = runtime_analysis.get(
        "network_indicator_count",
        0,
    )

    if static_network_count > 0 and runtime_network_count > 0:
        correlations.append(
            {
                "category": "network",
                "title": "Static and runtime network evidence both present",
                "confidence": "high",
                "reason": (
                    "Static analysis found network indicators and runtime "
                    "analysis also observed network-related log activity."
                ),
                "evidence": {
                    "static_network_indicator_count": static_network_count,
                    "runtime_network_indicator_count": runtime_network_count,
                },
            }
        )


def _add_permission_correlation(
    correlations: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
) -> None:
    """
    Correlate sensitive permissions with runtime permission/security events.
    """

    evidence = static_analysis.get("evidence", {})
    permissions = evidence.get("permissions", [])

    sensitive_permissions = [
        permission
        for permission in permissions
        if permission
        in {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        }
    ]

    runtime_security_count = runtime_analysis.get(
        "security_indicator_count",
        0,
    )

    permission_denial_count = runtime_analysis.get(
        "permission_denial_count",
        0,
    )

    if sensitive_permissions and (
        runtime_security_count > 0 or permission_denial_count > 0
    ):
        correlations.append(
            {
                "category": "permissions",
                "title": "Sensitive permissions and runtime security events observed",
                "confidence": "medium",
                "reason": (
                    "The APK requests sensitive permissions, and runtime logs "
                    "also contain security or permission-related events."
                ),
                "evidence": {
                    "sensitive_permissions": sensitive_permissions,
                    "runtime_security_indicator_count": runtime_security_count,
                    "permission_denial_count": permission_denial_count,
                },
            }
        )


def _add_runtime_activity_correlation(
    correlations: list[dict[str, Any]],
    behavior_analysis: dict[str, Any],
    runtime_analysis: dict[str, Any],
) -> None:
    """
    Correlate active app process state with runtime log activity.
    """

    behavior_flags = behavior_analysis.get("behavior_flags", {})
    app_active = behavior_analysis.get("app_active", False)
    detected_behavior_count = runtime_analysis.get(
        "behavior_summary",
        {},
    ).get("detected_behavior_count", 0)

    if app_active and detected_behavior_count > 0:
        correlations.append(
            {
                "category": "runtime_activity",
                "title": "Application was active while runtime behaviors were observed",
                "confidence": "high",
                "reason": (
                    "Behavior monitoring showed the app process or foreground "
                    "activity was active while runtime log behaviors were also "
                    "detected."
                ),
                "evidence": {
                    "app_active": app_active,
                    "behavior_flags": behavior_flags,
                    "detected_runtime_behavior_count": detected_behavior_count,
                },
            }
        )


def _add_service_correlation(
    correlations: list[dict[str, Any]],
    static_analysis: dict[str, Any],
    behavior_analysis: dict[str, Any],
) -> None:
    """
    Correlate declared service/component evidence with running services.
    """

    static_summary = static_analysis.get("summary", {})
    running_service_count = behavior_analysis.get(
        "running_service_count",
        0,
    )

    finding_count = static_summary.get("total_findings", 0)

    if finding_count > 0 and running_service_count > 0:
        correlations.append(
            {
                "category": "services",
                "title": "Static findings and runtime services both present",
                "confidence": "medium",
                "reason": (
                    "Static analysis found application findings, and behavior "
                    "monitoring observed app-related running service evidence."
                ),
                "evidence": {
                    "static_total_findings": finding_count,
                    "running_service_count": running_service_count,
                },
            }
        )


def _build_confidence_summary(
    correlations: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a summary of confidence levels across correlations.
    """

    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for correlation in correlations:
        confidence = correlation.get("confidence", "low")

        if confidence not in summary:
            confidence = "low"

        summary[confidence] += 1

    return summary