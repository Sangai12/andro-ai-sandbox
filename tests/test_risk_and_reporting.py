"""
Unit tests for AndroAI Sandbox risk and reporting modules.
"""

from copy import deepcopy

from backend.combined_risk_engine import calculate_combined_risk
from backend.dynamic_risk_score import calculate_dynamic_risk_score
from backend.final_ai_report_generator import generate_final_ai_report
from backend.report_sanitizer import sanitize_dynamic_workflow
from backend.report_validator import validate_final_report


def test_dynamic_risk_score_with_multiple_behaviors():
    runtime_analysis = {
        "behavior_summary": {
            "crash_detected": True,
            "exception_detected": True,
            "permission_denial_detected": True,
            "network_activity_detected": True,
            "webview_activity_detected": False,
            "security_event_detected": True,
            "warning_detected": False,
            "error_detected": True,
        },
    }

    result = calculate_dynamic_risk_score(runtime_analysis)

    assert result["dynamic_risk_score"] == 78
    assert result["dynamic_risk_level"] == "high"
    assert result["triggered_dynamic_rule_count"] == 6
    assert result["dynamic_severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 4,
        "low": 1,
    }


def test_dynamic_risk_score_defaults_to_low():
    result = calculate_dynamic_risk_score({})

    assert result["dynamic_risk_score"] == 0
    assert result["dynamic_risk_level"] == "low"
    assert result["triggered_dynamic_rule_count"] == 0
    assert result["triggered_dynamic_rules"] == []


def test_dynamic_risk_score_is_capped_at_100():
    runtime_analysis = {
        "behavior_summary": {
            "crash_detected": True,
            "exception_detected": True,
            "permission_denial_detected": True,
            "network_activity_detected": True,
            "webview_activity_detected": True,
            "security_event_detected": True,
            "warning_detected": True,
            "error_detected": True,
        },
    }

    result = calculate_dynamic_risk_score(runtime_analysis)

    assert result["dynamic_risk_score"] == 93
    assert result["dynamic_risk_level"] == "critical"
    assert result["triggered_dynamic_rule_count"] == 8


def test_combined_risk_uses_expected_weights():
    static_analysis = {
        "summary": {
            "risk_score": 70,
            "risk_level": "high",
        },
    }

    dynamic_risk = {
        "dynamic_risk_score": 40,
        "dynamic_risk_level": "medium",
    }

    result = calculate_combined_risk(
        static_analysis=static_analysis,
        dynamic_risk=dynamic_risk,
    )

    assert result["static_risk_score"] == 70
    assert result["dynamic_risk_score"] == 40
    assert result["overall_risk_score"] == 58
    assert result["overall_risk_level"] == "high"
    assert result["weights"] == {
        "static_weight": 0.6,
        "dynamic_weight": 0.4,
    }


def test_combined_risk_handles_missing_values():
    result = calculate_combined_risk(
        static_analysis={},
        dynamic_risk={},
    )

    assert result["static_risk_score"] == 0
    assert result["dynamic_risk_score"] == 0
    assert result["overall_risk_score"] == 0
    assert result["overall_risk_level"] == "low"


def test_report_validator_accepts_complete_report():
    final_report = _build_complete_report()

    result = validate_final_report(final_report)

    assert result["success"] is True
    assert result["validation_passed"] is True
    assert result["missing_sections"] == []
    assert result["empty_sections"] == []
    assert result["passed_quality_check_count"] == 7
    assert result["total_quality_check_count"] == 7
    assert result["report_quality_level"] == "complete"


def test_report_validator_detects_missing_sections():
    final_report = {
        "report_metadata": {
            "report_type": "final_static_dynamic_analysis",
        },
        "apk": {
            "package_name": "com.example.app",
        },
    }

    result = validate_final_report(final_report)

    assert result["success"] is True
    assert result["validation_passed"] is False
    assert "static_analysis" in result["missing_sections"]
    assert "dynamic_analysis" in result["missing_sections"]
    assert "ai_analyst_report" in result["missing_sections"]
    assert result["report_quality_level"] == "incomplete"


def test_report_validator_detects_empty_section():
    final_report = _build_complete_report()
    final_report["iocs"] = {}

    result = validate_final_report(final_report)

    assert result["validation_passed"] is True
    assert "iocs" in result["empty_sections"]
    assert result["quality_checks"]["has_iocs"] is False
    assert result["report_quality_level"] == "mostly_complete"


def test_report_sanitizer_removes_raw_stdout_and_limits_lists():
    workflow = {
        "behavior_snapshot": {
            "snapshot_path": "logs/example_behavior.json",
            "snapshot": {
                "raw_command_status": {
                    "processes": {
                        "success": True,
                        "stdout": "large process output",
                        "stderr": "",
                    },
                    "package_info": {
                        "success": True,
                        "stdout": "large package output",
                        "stderr": "",
                    },
                },
            },
        },
        "runtime_analysis": {
            "network_indicators": [
                f"network-{index}"
                for index in range(25)
            ],
            "warnings": [
                f"warning-{index}"
                for index in range(20)
            ],
        },
        "final_report": {
            "report": {
                "behavior_analysis": {
                    "processes": [
                        f"process-{index}"
                        for index in range(20)
                    ],
                    "foreground_activity": [
                        f"activity-{index}"
                        for index in range(20)
                    ],
                    "running_services": [
                        f"service-{index}"
                        for index in range(20)
                    ],
                },
                "iocs": {
                    "urls": [
                        f"https://example{index}.com"
                        for index in range(40)
                    ],
                    "domains": [
                        f"example{index}.com"
                        for index in range(40)
                    ],
                },
                "dynamic_mitre_attack": [
                    {
                        "technique_id": "T1437",
                        "evidence": [
                            f"evidence-{index}"
                            for index in range(10)
                        ],
                    },
                ],
            },
        },
    }

    original_workflow = deepcopy(workflow)

    result = sanitize_dynamic_workflow(workflow)

    raw_status = result["behavior_snapshot"]["snapshot"][
        "raw_command_status"
    ]

    assert "stdout" not in raw_status["processes"]
    assert "stdout" not in raw_status["package_info"]
    assert len(result["runtime_analysis"]["network_indicators"]) == 15
    assert len(result["runtime_analysis"]["warnings"]) == 15
    assert (
        len(
            result["final_report"]["report"]["behavior_analysis"][
                "processes"
            ]
        )
        == 15
    )
    assert len(result["final_report"]["report"]["iocs"]["urls"]) == 30
    assert (
        len(
            result["final_report"]["report"]["dynamic_mitre_attack"][0][
                "evidence"
            ]
        )
        == 5
    )

    assert (
        original_workflow["behavior_snapshot"]["snapshot"][
            "raw_command_status"
        ]["processes"]["stdout"]
        == "large process output"
    )


def test_final_ai_report_uses_only_provided_evidence():
    final_report = _build_complete_report()

    result = generate_final_ai_report(final_report)

    assert "com.example.app" in result["executive_summary"]
    assert "high risk level" in result["executive_summary"]
    assert "score of 70" in result["executive_summary"]
    assert "medium risk level" in result["executive_summary"]
    assert "score of 40" in result["executive_summary"]
    assert "overall risk level is high" in result["executive_summary"]
    assert "overall score of 58" in result["executive_summary"]

    assert result["static_findings_summary"]["risk_score"] == 70
    assert result["static_findings_summary"]["finding_count"] == 4
    assert result["static_findings_summary"]["mitre_attack_count"] == 2

    assert (
        result["dynamic_behavior_summary"][
            "network_activity_detected"
        ]
        is True
    )
    assert (
        result["dynamic_behavior_summary"]["counts"][
            "network_indicators"
        ]
        == 2
    )

    assert "static analysis weighted at 0.6" in result["risk_explanation"]
    assert "dynamic analysis weighted at 0.4" in result["risk_explanation"]

    assert (
        "Prioritize this sample for deeper manual analysis because "
        "the combined risk level is elevated."
        in result["recommended_next_steps"]
    )
    assert "human analyst" in result["disclaimer"]


def test_final_ai_report_adds_exception_and_security_recommendations():
    final_report = _build_complete_report()

    behavior_summary = final_report["dynamic_analysis"][
        "behavior_summary"
    ]

    behavior_summary["exception_detected"] = True
    behavior_summary["security_event_detected"] = True

    result = generate_final_ai_report(final_report)

    recommendations = result["recommended_next_steps"]

    assert any(
        recommendation.startswith("Investigate runtime exceptions")
        for recommendation in recommendations
    )

    assert any(
        recommendation.startswith(
            "Review security-related runtime events"
        )
        for recommendation in recommendations
    )


def _build_complete_report() -> dict:
    """
    Build a valid deterministic final report fixture.
    """

    return {
        "report_metadata": {
            "report_type": "final_static_dynamic_analysis",
            "analyzer_name": "AndroAI Sandbox",
            "analyzer_version": "0.1.0",
            "generated_at": "2026-07-10T12:00:00+00:00",
        },
        "apk": {
            "apk_path": "uploads/example.apk",
            "package_name": "com.example.app",
        },
        "static_analysis": {
            "summary": {
                "risk_level": "high",
                "risk_score": 70,
                "total_findings": 4,
                "severity_counts": {
                    "critical": 0,
                    "high": 2,
                    "medium": 1,
                    "low": 1,
                },
                "risk_summary": (
                    "Static evidence contains security-relevant findings."
                ),
            },
            "finding_count": 4,
            "mitre_attack_count": 2,
        },
        "dynamic_analysis": {
            "behavior_summary": {
                "detected_behaviors": [
                    "network_activity",
                    "warning",
                ],
                "detected_behavior_count": 2,
                "crash_detected": False,
                "exception_detected": False,
                "network_activity_detected": True,
                "webview_activity_detected": False,
                "security_event_detected": False,
                "warning_detected": True,
                "error_detected": False,
            },
            "crash_count": 0,
            "exception_count": 0,
            "permission_denial_count": 0,
            "network_indicator_count": 2,
            "webview_indicator_count": 0,
            "security_indicator_count": 0,
            "warning_count": 1,
            "error_count": 0,
            "log_path": "logs/example.log",
        },
        "behavior_analysis": {
            "success": True,
            "app_active": True,
            "process_count": 1,
        },
        "dynamic_mitre_attack": [
            {
                "technique_id": "T1437",
                "technique_name": "Application Layer Protocol",
                "evidence": [
                    "Network activity detected",
                ],
            },
        ],
        "evidence_correlation": {
            "success": True,
            "correlation_count": 1,
        },
        "iocs": {
            "urls": [
                "https://api.example.com",
            ],
            "url_count": 1,
        },
        "dynamic_risk": {
            "dynamic_risk_score": 40,
            "dynamic_risk_level": "medium",
        },
        "combined_risk": {
            "static_risk_score": 70,
            "static_risk_level": "high",
            "dynamic_risk_score": 40,
            "dynamic_risk_level": "medium",
            "overall_risk_score": 58,
            "overall_risk_level": "high",
            "weights": {
                "static_weight": 0.6,
                "dynamic_weight": 0.4,
            },
        },
        "ai_analyst_report": {
            "executive_summary": "Existing AI report.",
        },
    }