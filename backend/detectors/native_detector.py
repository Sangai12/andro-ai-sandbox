"""
AndroAI Sandbox - Native Detector

This module evaluates native libraries and returns
evidence-based findings.

Phase 12.2 scope:
- Detect suspicious native library names
- Detect native library presence
- Detect multiple CPU architectures
"""

from typing import Any


def detect_native_findings(
    native_analysis: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Analyze native library metadata and return findings.
    """

    findings: list[dict[str, str]] = []

    native_libraries = native_analysis.get("native_libraries", [])
    native_architectures = native_analysis.get("native_architectures", [])

    if native_libraries:
        findings.append(
            {
                "id": "NATIVE_LIBRARIES_PRESENT",
                "title": "Native Libraries Present",
                "severity": "low",
                "evidence_type": "native_library",
                "evidence": f"native_library_count={len(native_libraries)}",
            }
        )

    if len(native_architectures) > 1:
        findings.append(
            {
                "id": "NATIVE_MULTIPLE_ARCHITECTURES",
                "title": "Multiple Native CPU Architectures Detected",
                "severity": "low",
                "evidence_type": "native_architecture",
                "evidence": ",".join(native_architectures),
            }
        )

    suspicious_names = [
        "frida",
        "xposed",
        "substrate",
        "magisk",
        "hook",
        "inject",
        "packer",
        "protect",
        "shell",
        "loader",
    ]

    for library in native_libraries:
        library_lower = library.lower()

        for suspicious_name in suspicious_names:
            if suspicious_name in library_lower:
                findings.append(
                    {
                        "id": "NATIVE_SUSPICIOUS_LIBRARY",
                        "title": "Suspicious Native Library Name Detected",
                        "severity": "high",
                        "evidence_type": "native_library",
                        "evidence": library,
                    }
                )
                break

    return findings