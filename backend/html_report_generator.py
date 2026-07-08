"""
AndroAI Sandbox - HTML Report Generator

This module converts structured analysis reports into
professional HTML analyst reports.

Phase 25 scope:
- Generate basic HTML report
- Include APK summary
- Include risk summary
- Include findings table
- Include MITRE ATT&CK mapping table
"""

from html import escape
from typing import Any


def generate_html_report(
    report: dict[str, Any],
) -> str:
    """
    Generate an HTML report from a structured analysis report.
    """

    apk = report.get("apk", {})
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    mitre_attack = report.get("mitre_attack", [])

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{escape(finding.get("severity", ""))}</td>
            <td>{escape(finding.get("confidence", ""))}</td>
            <td>{escape(finding.get("title", ""))}</td>
            <td>{escape(finding.get("evidence_type", ""))}</td>
            <td>{escape(finding.get("evidence", ""))}</td>
        </tr>
        """

    mitre_rows = ""

    for item in mitre_attack:
        mitre_rows += f"""
        <tr>
            <td>{escape(item.get("technique_id", ""))}</td>
            <td>{escape(item.get("technique_name", ""))}</td>
            <td>{escape(item.get("finding_id", ""))}</td>
            <td>{escape(item.get("evidence", ""))}</td>
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
            margin: 40px;
            color: #222;
        }}
        h1, h2 {{
            color: #1f2937;
        }}
        .card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
            background: #fafafa;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
            font-size: 14px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #f1f5f9;
        }}
        .risk {{
            font-size: 20px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>AndroAI Sandbox Analysis Report</h1>

    <div class="card">
        <h2>APK Summary</h2>
        <p><strong>Package:</strong> {escape(apk.get("package_name", ""))}</p>
        <p><strong>Version:</strong> {escape(str(apk.get("version_name", "")))}</p>
        <p><strong>Version Code:</strong> {escape(str(apk.get("version_code", "")))}</p>
        <p><strong>Min SDK:</strong> {escape(str(apk.get("min_sdk", "")))}</p>
        <p><strong>Target SDK:</strong> {escape(str(apk.get("target_sdk", "")))}</p>
    </div>

    <div class="card">
        <h2>Risk Summary</h2>
        <p class="risk">Risk Level: {escape(summary.get("risk_level", ""))}</p>
        <p><strong>Risk Score:</strong> {escape(str(summary.get("risk_score", "")))}</p>
        <p>{escape(summary.get("risk_summary", ""))}</p>
        <p><strong>Total Findings:</strong> {escape(str(summary.get("total_findings", "")))}</p>
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

</body>
</html>
"""