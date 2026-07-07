"""
AndroAI Sandbox - MITRE ATT&CK Mapper

Maps evidence-based findings to relevant
MITRE ATT&CK Mobile techniques.

Phase 23.1 scope:
- Map findings to ATT&CK IDs
- Preserve evidence
- Do not infer unsupported techniques
"""

from typing import Any


def map_findings_to_mitre(
    findings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """
    Map findings to MITRE ATT&CK Mobile techniques.
    """

    mapping_rules = {
        "PERM_CAMERA": ("T1513", "Camera Capture"),
        "PERM_RECORD_AUDIO": ("T1429", "Audio Capture"),
        "PERM_FINE_LOCATION": ("T1430", "Location Tracking"),
        "PERM_COARSE_LOCATION": ("T1430", "Location Tracking"),
        "PERM_READ_EXTERNAL_STORAGE": ("T1636", "Protected User Data"),
        "PERM_WRITE_EXTERNAL_STORAGE": ("T1636", "Protected User Data"),
        "PERM_QUERY_ALL_PACKAGES": ("T1426", "System Information Discovery"),
        "PERM_BOOT_COMPLETED": ("T1624", "Event Triggered Execution"),

        "MANIFEST_EXPORTED_ACTIVITY": (
            "T1418",
            "Application Discovery",
        ),
        "MANIFEST_EXPORTED_SERVICE": (
            "T1418",
            "Application Discovery",
        ),
        "MANIFEST_EXPORTED_RECEIVER": (
            "T1418",
            "Application Discovery",
        ),
        "MANIFEST_BOOT_RECEIVER": (
            "T1624",
            "Event Triggered Execution",
        ),

        "DEX_MULTIPLE_FILES": (
            "T1620",
            "Reflective Code Loading",
        ),

        "CODE_DYNAMIC_LOADING": (
            "T1620",
            "Reflective Code Loading",
        ),
        "CODE_REFLECTION": (
            "T1620",
            "Reflective Code Loading",
        ),
        "CODE_WEBVIEW_JS_BRIDGE": (
            "T1456",
            "WebView Abuse",
        ),
        "CODE_ROOT_INDICATOR": (
            "T1626",
            "Abuse Elevation Control Mechanism",
        ),

        "YARA_RULE_MATCH": (
            "T1587",
            "Develop Capabilities",
        ),
    }

    mitre_results: list[dict[str, Any]] = []

    for finding in findings:
        rule = mapping_rules.get(finding.get("id"))

        if not rule:
            continue

        technique_id, technique_name = rule

        mitre_results.append(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "finding_id": finding["id"],
                "finding_title": finding["title"],
                "evidence": finding["evidence"],
            }
        )

    return mitre_results