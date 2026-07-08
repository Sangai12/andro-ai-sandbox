"""
AndroAI Sandbox - PDF Report Generator

This module converts structured analysis reports into
professional PDF analyst reports.

Phase 27 scope:
- Generate PDF report
- Include APK summary
- Include risk summary
- Include evidence overview
- Include findings table
- Include MITRE ATT&CK mapping table
"""

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> str:
    """
    Generate a PDF report from a structured analysis report.
    """

    output_file = Path(output_path)

    doc = SimpleDocTemplate(
        str(output_file),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    story = []

    apk = report.get("apk", {})
    summary = report.get("summary", {})
    evidence = report.get("evidence", {})
    findings = report.get("findings", [])
    mitre_attack = report.get("mitre_attack", [])

    story.append(Paragraph("AndroAI Sandbox Analysis Report", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("APK Summary", styles["Heading2"]))
    apk_data = [
        ["Package", apk.get("package_name", "")],
        ["Version", apk.get("version_name", "")],
        ["Version Code", apk.get("version_code", "")],
        ["Min SDK", apk.get("min_sdk", "")],
        ["Target SDK", apk.get("target_sdk", "")],
    ]
    story.append(_build_key_value_table(apk_data))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Risk Summary", styles["Heading2"]))
    risk_data = [
        ["Risk Level", summary.get("risk_level", "")],
        ["Risk Score", str(summary.get("risk_score", ""))],
        ["Total Findings", str(summary.get("total_findings", ""))],
    ]
    story.append(_build_key_value_table(risk_data))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            str(summary.get("risk_summary", "")),
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Evidence Overview", styles["Heading2"]))
    evidence_data = [
        ["Permissions", str(evidence.get("permission_count", 0))],
        ["Activities", str(evidence.get("activity_count", 0))],
        ["Services", str(evidence.get("service_count", 0))],
        ["Receivers", str(evidence.get("receiver_count", 0))],
        ["Providers", str(evidence.get("provider_count", 0))],
        ["URLs", str(evidence.get("url_count", 0))],
        ["Domains", str(evidence.get("domain_count", 0))],
        ["YARA Matches", str(evidence.get("yara_match_count", 0))],
    ]
    story.append(_build_key_value_table(evidence_data))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", styles["Heading2"]))
    findings_data = [["Severity", "Confidence", "Title", "Evidence Type"]]

    for finding in findings[:40]:
        findings_data.append(
            [
                finding.get("severity", ""),
                finding.get("confidence", ""),
                finding.get("title", ""),
                finding.get("evidence_type", ""),
            ]
        )

    story.append(_build_table(findings_data))
    story.append(Spacer(1, 12))

    story.append(Paragraph("MITRE ATT&CK Mapping", styles["Heading2"]))
    mitre_data = [["Technique ID", "Technique Name", "Finding ID"]]

    for item in mitre_attack[:40]:
        mitre_data.append(
            [
                item.get("technique_id", ""),
                item.get("technique_name", ""),
                item.get("finding_id", ""),
            ]
        )

    story.append(_build_table(mitre_data))
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "This report is evidence-based. Findings indicate areas requiring "
            "analysis and do not prove malicious behavior by themselves.",
            styles["Italic"],
        )
    )

    doc.build(story)

    return str(output_file)


def _build_key_value_table(
    rows: list[list[str]],
) -> Table:
    """
    Build a two-column key-value table.
    """

    table = Table(rows, colWidths=[140, 360])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _build_table(
    rows: list[list[str]],
) -> Table:
    """
    Build a styled report table.
    """

    table = Table(rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table