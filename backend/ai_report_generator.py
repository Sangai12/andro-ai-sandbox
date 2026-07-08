"""
AndroAI Sandbox - AI Report Generator

This module generates evidence-based AI-style analyst summaries
from structured analysis reports.

Phase 28.1 scope:
- Generate deterministic analyst summary
- Use only existing report evidence
- Avoid unsupported conclusions
- Prepare structure for future LLM integration
"""

from typing import Any


def generate_ai_summary(
    report: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate an evidence-based analyst summary from a structured report.
    """

    summary = report.get("summary", {})
    evidence = report.get("evidence", {})
    findings = report.get("findings", [])
    mitre_attack = report.get("mitre_attack", [])

    risk_level = summary.get("risk_level", "unknown")
    risk_score = summary.get("risk_score", 0)
    total_findings = summary.get("total_findings", 0)

    high_findings = [
        finding
        for finding in findings
        if finding.get("severity") == "high"
    ]

    medium_findings = [
        finding
        for finding in findings
        if finding.get("severity") == "medium"
    ]

    key_evidence = _build_key_evidence_summary(evidence)
    key_behaviors = _build_key_behavior_summary(findings)
    mitre_summary = _build_mitre_summary(mitre_attack)

    executive_summary = (
        f"The APK was assessed with a risk level of {risk_level} "
        f"and a risk score of {risk_score}. The analysis identified "
        f"{total_findings} evidence-based findings, including "
        f"{len(high_findings)} high-severity findings and "
        f"{len(medium_findings)} medium-severity findings. "
        "These findings do not prove malicious behavior by themselves, "
        "but they identify areas that require further analyst review."
    )

    analyst_assessment = (
        "The static analysis results indicate that the APK contains "
        "multiple security-relevant characteristics. The assessment is "
        "based on observable evidence such as permissions, manifest "
        "components, extracted indicators, code strings, YARA rule matches, "
        "and MITRE ATT&CK mappings."
    )

    recommended_next_steps = [
        "Review high-severity findings first.",
        "Validate exported components against expected application behavior.",
        "Review network indicators for suspicious or unexpected destinations.",
        "Investigate YARA matches to confirm whether they represent true positives.",
        "Perform dynamic analysis before making a final malicious/benign conclusion.",
    ]

    return {
        "executive_summary": executive_summary,
        "analyst_assessment": analyst_assessment,
        "key_evidence": key_evidence,
        "key_behaviors": key_behaviors,
        "mitre_summary": mitre_summary,
        "recommended_next_steps": recommended_next_steps,
        "disclaimer": (
            "This AI-style summary is generated only from existing "
            "analysis evidence. It does not introduce unsupported claims."
        ),
    }


def _build_key_evidence_summary(
    evidence: dict[str, Any],
) -> list[str]:
    """
    Build key evidence bullets from evidence counts.
    """

    return [
        f"Permissions requested: {evidence.get('permission_count', 0)}",
        f"Activities discovered: {evidence.get('activity_count', 0)}",
        f"Services discovered: {evidence.get('service_count', 0)}",
        f"Receivers discovered: {evidence.get('receiver_count', 0)}",
        f"Providers discovered: {evidence.get('provider_count', 0)}",
        f"URLs extracted: {evidence.get('url_count', 0)}",
        f"Domains extracted: {evidence.get('domain_count', 0)}",
        f"YARA rule matches: {evidence.get('yara_match_count', 0)}",
    ]


def _build_key_behavior_summary(
    findings: list[dict[str, Any]],
) -> list[str]:
    """
    Summarize major behavior categories from findings.
    """

    behavior_map = {
        "permission": "Sensitive permission usage",
        "manifest_component": "Exported application components",
        "manifest_intent_filter": "Persistence-related manifest entries",
        "native_library": "Native library usage",
        "native_architecture": "Multiple native CPU architectures",
        "dex": "DEX structure indicators",
        "url": "Network indicators",
        "ip_address": "IP address indicators",
        "certificate": "Certificate-related findings",
        "code_string": "Code or root-related strings",
        "yara_rule": "YARA signature matches",
        "api_usage": "Sensitive API usage",
    }

    observed_behaviors = sorted(
        {
            behavior_map.get(finding.get("evidence_type", ""), "Other evidence")
            for finding in findings
        }
    )

    return observed_behaviors


def _build_mitre_summary(
    mitre_attack: list[dict[str, Any]],
) -> list[str]:
    """
    Summarize unique MITRE ATT&CK technique mappings.
    """

    techniques = sorted(
        {
            (
                item.get("technique_id", "unknown"),
                item.get("technique_name", "Unknown Technique"),
            )
            for item in mitre_attack
        }
    )

    return [
        f"{technique_id}: {technique_name}"
        for technique_id, technique_name in techniques
    ]