"""
AndroAI Sandbox - HTML Report Generator

This module converts structured analysis reports into
professional HTML analyst reports.
"""

from html import escape
from typing import Any


def _badge(value: str, badge_type: str) -> str:
    """
    Create a styled badge for severity, confidence, or risk.
    """

    safe_value = escape(str(value).lower())

    return f'<span class="badge {badge_type}-{safe_value}">{safe_value}</span>'


def _list_items(items: list[str]) -> str:
    """
    Convert a list of strings into escaped HTML list items.
    """

    return "".join(
        f"<li>{escape(str(item))}</li>"
        for item in items
    )


def generate_html_report(
    report: dict[str, Any],
) -> str:
    """
    Generate an HTML report from a structured analysis report.
    """

    report_metadata = report.get("report_metadata", {})
    apk = report.get("apk", {})
    summary = report.get("summary", {})
    evidence = report.get("evidence", {})
    findings = report.get("findings", [])
    mitre_attack = report.get("mitre_attack", [])
    ai_summary = report.get("ai_summary", {})
    severity_counts = summary.get("severity_counts", {})

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{_badge(finding.get("severity", ""), "severity")}</td>
            <td>{_badge(finding.get("confidence", ""), "confidence")}</td>
            <td>{escape(str(finding.get("title", "")))}</td>
            <td>{escape(str(finding.get("evidence_type", "")))}</td>
            <td class="evidence">{escape(str(finding.get("evidence", "")))}</td>
        </tr>
        """

    mitre_rows = ""

    for item in mitre_attack:
        mitre_rows += f"""
        <tr>
            <td><strong>{escape(str(item.get("technique_id", "")))}</strong></td>
            <td>{escape(str(item.get("technique_name", "")))}</td>
            <td>{escape(str(item.get("finding_id", "")))}</td>
            <td class="evidence">{escape(str(item.get("evidence", "")))}</td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AndroAI Sandbox Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            background: #f3f4f6;
            color: #111827;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px;
        }}

        .header {{
            background: #111827;
            color: white;
            padding: 28px 32px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}

        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}

        .header p {{
            margin: 8px 0 0;
            color: #d1d5db;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}

        .metric-card {{
            background: white;
            border-radius: 12px;
            padding: 18px;
            border: 1px solid #e5e7eb;
        }}

        .metric-label {{
            color: #6b7280;
            font-size: 13px;
            margin-bottom: 8px;
        }}

        .metric-value {{
            font-size: 24px;
            font-weight: bold;
        }}

        .card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 24px;
        }}

        h2 {{
            margin-top: 0;
            color: #111827;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
        }}

        h3 {{
            color: #374151;
            margin-bottom: 8px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 12px;
            font-size: 14px;
        }}

        th, td {{
            border-bottom: 1px solid #e5e7eb;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #f9fafb;
            color: #374151;
        }}

        tr:hover {{
            background: #f9fafb;
        }}

        ul, ol {{
            line-height: 1.7;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 9px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity-critical,
        .risk-critical {{
            background: #7f1d1d;
            color: white;
        }}

        .severity-high,
        .risk-high {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .severity-medium,
        .risk-medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .severity-low,
        .risk-low {{
            background: #dcfce7;
            color: #166534;
        }}

        .confidence-high {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .confidence-medium {{
            background: #ede9fe;
            color: #5b21b6;
        }}

        .confidence-low {{
            background: #e5e7eb;
            color: #374151;
        }}

        .evidence {{
            font-family: monospace;
            font-size: 13px;
            word-break: break-word;
        }}

        .muted {{
            color: #6b7280;
            font-size: 13px;
        }}

        .summary-text {{
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AndroAI Sandbox Analysis Report</h1>
            <p>Evidence-based Android APK static analysis report</p>
        </div>

        <div class="grid">
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value">
                    {_badge(summary.get("risk_level", ""), "risk")}
                </div>
            </div>

            <div class="metric-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">
                    {escape(str(summary.get("risk_score", "")))}
                </div>
            </div>

            <div class="metric-card">
                <div class="metric-label">Total Findings</div>
                <div class="metric-value">
                    {escape(str(summary.get("total_findings", "")))}
                </div>
            </div>

            <div class="metric-card">
                <div class="metric-label">MITRE Mappings</div>
                <div class="metric-value">
                    {escape(str(report.get("mitre_attack_count", "")))}
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Report Metadata</h2>
            <p><strong>Analyzer:</strong> {escape(str(report_metadata.get("analyzer_name", "")))}</p>
            <p><strong>Analyzer Version:</strong> {escape(str(report_metadata.get("analyzer_version", "")))}</p>
            <p><strong>Report Version:</strong> {escape(str(report_metadata.get("report_version", "")))}</p>
            <p><strong>Generated At:</strong> {escape(str(report_metadata.get("generated_at", "")))}</p>
        </div>

        <div class="card">
            <h2>APK Summary</h2>
            <p><strong>Package:</strong> {escape(str(apk.get("package_name", "")))}</p>
            <p><strong>Version:</strong> {escape(str(apk.get("version_name", "")))}</p>
            <p><strong>Version Code:</strong> {escape(str(apk.get("version_code", "")))}</p>
            <p><strong>Min SDK:</strong> {escape(str(apk.get("min_sdk", "")))}</p>
            <p><strong>Target SDK:</strong> {escape(str(apk.get("target_sdk", "")))}</p>
        </div>

        <div class="card">
            <h2>Risk Summary</h2>
            <p class="summary-text">{escape(str(summary.get("risk_summary", "")))}</p>
            <p>
                <strong>Low:</strong> {escape(str(severity_counts.get("low", 0)))}
                &nbsp; | &nbsp;
                <strong>Medium:</strong> {escape(str(severity_counts.get("medium", 0)))}
                &nbsp; | &nbsp;
                <strong>High:</strong> {escape(str(severity_counts.get("high", 0)))}
                &nbsp; | &nbsp;
                <strong>Critical:</strong> {escape(str(severity_counts.get("critical", 0)))}
            </p>
        </div>

        <div class="card">
            <h2>AI Analyst Summary</h2>

            <h3>Executive Summary</h3>
            <p class="summary-text">
                {escape(str(ai_summary.get("executive_summary", "")))}
            </p>

            <h3>Analyst Assessment</h3>
            <p class="summary-text">
                {escape(str(ai_summary.get("analyst_assessment", "")))}
            </p>

            <h3>Key Evidence</h3>
            <ul>
                {_list_items(ai_summary.get("key_evidence", []))}
            </ul>

            <h3>Observed Behaviors</h3>
            <ul>
                {_list_items(ai_summary.get("key_behaviors", []))}
            </ul>

            <h3>MITRE ATT&CK Summary</h3>
            <ul>
                {_list_items(ai_summary.get("mitre_summary", []))}
            </ul>

            <h3>Recommended Next Steps</h3>
            <ol>
                {_list_items(ai_summary.get("recommended_next_steps", []))}
            </ol>

            <p class="muted">
                {escape(str(ai_summary.get("disclaimer", "")))}
            </p>
        </div>

        <div class="card">
            <h2>Evidence Overview</h2>
            <p><strong>Permissions:</strong> {escape(str(evidence.get("permission_count", 0)))}</p>
            <p><strong>Activities:</strong> {escape(str(evidence.get("activity_count", 0)))}</p>
            <p><strong>Services:</strong> {escape(str(evidence.get("service_count", 0)))}</p>
            <p><strong>Receivers:</strong> {escape(str(evidence.get("receiver_count", 0)))}</p>
            <p><strong>Providers:</strong> {escape(str(evidence.get("provider_count", 0)))}</p>
            <p><strong>URLs:</strong> {escape(str(evidence.get("url_count", 0)))}</p>
            <p><strong>Domains:</strong> {escape(str(evidence.get("domain_count", 0)))}</p>
            <p><strong>YARA Matches:</strong> {escape(str(evidence.get("yara_match_count", 0)))}</p>
        </div>

        <div class="card">
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Title</th>
                    <th>Evidence Type</th>
                    <th>Evidence</th>
                </tr>
                {finding_rows}
            </table>
        </div>

        <div class="card">
            <h2>MITRE ATT&CK Mapping</h2>
            <table>
                <tr>
                    <th>Technique ID</th>
                    <th>Technique Name</th>
                    <th>Finding ID</th>
                    <th>Evidence</th>
                </tr>
                {mitre_rows}
            </table>
        </div>

        <p class="muted">
            This report is evidence-based. Findings indicate areas requiring
            analysis and do not prove malicious behavior by themselves.
        </p>
    </div>
</body>
</html>
"""