"""
AndroAI Sandbox - Runtime Log Analyzer

This module extracts structured runtime behavior indicators
from saved Android logcat files.

Phase 33 and Phase 35 scope:
- Read saved logcat logs
- Detect crashes and exceptions
- Detect permission denials
- Detect network-related log entries
- Detect WebView-related log entries
- Detect security-related log entries
- Classify runtime behavior into clean behavior flags
- Build structured dynamic evidence
"""

from pathlib import Path
from typing import Any


def analyze_runtime_log(
    log_path: str | Path,
) -> dict[str, Any]:
    """
    Analyze a saved logcat file and extract runtime behavior evidence.
    """

    log_file = Path(log_path)

    if not log_file.exists():
        return {
            "success": False,
            "log_path": str(log_file),
            "message": "Runtime log file not found.",
        }

    log_text = log_file.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    lines = log_text.splitlines()

    crash_lines = _find_matching_lines(
        lines,
        [
            "FATAL EXCEPTION",
            "AndroidRuntime",
            "Force finishing activity",
            "Process crashed",
        ],
    )

    exception_lines = _find_matching_lines(
        lines,
        [
            "Exception",
            "java.lang.",
            "NullPointerException",
            "SecurityException",
            "IllegalStateException",
        ],
    )

    permission_denial_lines = _find_matching_lines(
        lines,
        [
            "Permission Denial",
            "permission denied",
            "denied permission",
            "SecurityException",
        ],
    )

    network_lines = _find_matching_lines(
        lines,
        [
            "http://",
            "https://",
            "socket",
            "connect",
            "dns",
            "network",
            "ssl",
            "tls",
        ],
    )

    webview_lines = _find_matching_lines(
        lines,
        [
            "WebView",
            "chromium",
            "javascript",
            "console",
        ],
    )

    security_lines = _find_matching_lines(
        lines,
        [
            "SELinux",
            "avc: denied",
            "root",
            "su",
            "debugger",
            "frida",
            "xposed",
        ],
    )

    warning_lines = _find_matching_lines(
        lines,
        [
            " W ",
            " WARN ",
            "Warning",
        ],
    )

    error_lines = _find_matching_lines(
        lines,
        [
            " E ",
            " ERROR ",
            "Error",
        ],
    )

    behavior_summary = _build_behavior_summary(
        crash_count=len(crash_lines),
        exception_count=len(exception_lines),
        permission_denial_count=len(permission_denial_lines),
        network_indicator_count=len(network_lines),
        webview_indicator_count=len(webview_lines),
        security_indicator_count=len(security_lines),
        warning_count=len(warning_lines),
        error_count=len(error_lines),
    )

    return {
        "success": True,
        "log_path": str(log_file),
        "line_count": len(lines),
        "behavior_summary": behavior_summary,
        "crashes": crash_lines,
        "crash_count": len(crash_lines),
        "exceptions": exception_lines,
        "exception_count": len(exception_lines),
        "permission_denials": permission_denial_lines,
        "permission_denial_count": len(permission_denial_lines),
        "network_indicators": network_lines,
        "network_indicator_count": len(network_lines),
        "webview_indicators": webview_lines,
        "webview_indicator_count": len(webview_lines),
        "security_indicators": security_lines,
        "security_indicator_count": len(security_lines),
        "warnings": warning_lines,
        "warning_count": len(warning_lines),
        "errors": error_lines,
        "error_count": len(error_lines),
        "message": "Runtime log analyzed successfully.",
    }


def _build_behavior_summary(
    crash_count: int,
    exception_count: int,
    permission_denial_count: int,
    network_indicator_count: int,
    webview_indicator_count: int,
    security_indicator_count: int,
    warning_count: int,
    error_count: int,
) -> dict[str, Any]:
    """
    Build clean runtime behavior flags from detected evidence counts.
    """

    detected_behaviors = []

    behavior_flags = {
        "crash_detected": crash_count > 0,
        "exception_detected": exception_count > 0,
        "permission_denial_detected": permission_denial_count > 0,
        "network_activity_detected": network_indicator_count > 0,
        "webview_activity_detected": webview_indicator_count > 0,
        "security_event_detected": security_indicator_count > 0,
        "warning_detected": warning_count > 0,
        "error_detected": error_count > 0,
    }

    behavior_labels = {
        "crash_detected": "Runtime crash behavior",
        "exception_detected": "Runtime exception behavior",
        "permission_denial_detected": "Permission denial behavior",
        "network_activity_detected": "Network activity behavior",
        "webview_activity_detected": "WebView or browser activity behavior",
        "security_event_detected": "Security-related runtime behavior",
        "warning_detected": "Runtime warning behavior",
        "error_detected": "Runtime error behavior",
    }

    for flag, detected in behavior_flags.items():
        if detected:
            detected_behaviors.append(behavior_labels[flag])

    return {
        **behavior_flags,
        "detected_behaviors": detected_behaviors,
        "detected_behavior_count": len(detected_behaviors),
    }


def _find_matching_lines(
    lines: list[str],
    keywords: list[str],
    limit: int = 50,
) -> list[str]:
    """
    Return log lines matching any keyword.
    """

    matches: list[str] = []

    for line in lines:
        line_lower = line.lower()

        if any(keyword.lower() in line_lower for keyword in keywords):
            matches.append(line.strip())

        if len(matches) >= limit:
            break

    return matches