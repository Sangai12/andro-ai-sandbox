"""
AndroAI Sandbox - Runtime Log Analyzer

This module extracts structured runtime behavior indicators
from saved Android logcat files.

Current scope:
- Read saved package-filtered logcat logs
- Detect crashes and exceptions
- Detect permission denials
- Detect network-related log entries
- Detect WebView-related log entries
- Detect security-related log entries
- Reduce false positives from broad substring matching
- Build structured dynamic evidence
"""

from pathlib import Path
import re
from typing import Any


CRASH_PATTERNS = [
    re.compile(r"\bfatal exception\b", re.IGNORECASE),
    re.compile(r"\bforce finishing activity\b", re.IGNORECASE),
    re.compile(r"\bprocess crashed\b", re.IGNORECASE),
    re.compile(r"\bfatal signal\b", re.IGNORECASE),
]

EXCEPTION_PATTERNS = [
    re.compile(r"\bexception\b", re.IGNORECASE),
    re.compile(r"\bjava\.[a-z0-9_.]+exception\b", re.IGNORECASE),
    re.compile(r"\bnullpointerexception\b", re.IGNORECASE),
    re.compile(r"\bsecurityexception\b", re.IGNORECASE),
    re.compile(r"\billegalstateexception\b", re.IGNORECASE),
]

PERMISSION_DENIAL_PATTERNS = [
    re.compile(r"\bpermission denial\b", re.IGNORECASE),
    re.compile(r"\bpermission denied\b", re.IGNORECASE),
    re.compile(r"\bdenied permission\b", re.IGNORECASE),
    re.compile(r"\bsecurityexception\b", re.IGNORECASE),
]

NETWORK_PATTERNS = [
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\bconnecting to\b", re.IGNORECASE),
    re.compile(r"\bconnection (?:opened|established|failed)\b", re.IGNORECASE),
    re.compile(r"\bsocket\b", re.IGNORECASE),
    re.compile(r"\bdns\b", re.IGNORECASE),
    re.compile(r"\bgetaddrinfo\b", re.IGNORECASE),
    re.compile(r"\bssl\b", re.IGNORECASE),
    re.compile(r"\btls\b", re.IGNORECASE),
    re.compile(r"\bhandshake\b", re.IGNORECASE),
    re.compile(r"\bunknownhostexception\b", re.IGNORECASE),
]

WEBVIEW_PATTERNS = [
    re.compile(r"\bwebview\b", re.IGNORECASE),
    re.compile(r"\bchromium\b", re.IGNORECASE),
    re.compile(r"\bjavascript\b", re.IGNORECASE),
    re.compile(r"\bconsole\.(?:log|warn|error)\b", re.IGNORECASE),
]

SECURITY_PATTERNS = [
    re.compile(r"\bselinux\b", re.IGNORECASE),
    re.compile(r"\bavc:\s*denied\b", re.IGNORECASE),
    re.compile(r"\bfrida\b", re.IGNORECASE),
    re.compile(r"\bxposed\b", re.IGNORECASE),
    re.compile(r"\bmagisk\b", re.IGNORECASE),
    re.compile(r"\bdebugger detected\b", re.IGNORECASE),
    re.compile(r"\broot detected\b", re.IGNORECASE),
    re.compile(r"\broot access\b", re.IGNORECASE),
    re.compile(r"\bsu binary\b", re.IGNORECASE),
]

WARNING_PATTERNS = [
    re.compile(
        r"^\S+\s+\S+\s+\d+\s+\d+\s+W\s+",
        re.IGNORECASE,
    ),
    re.compile(r"\bWARN(?:ING)?\s*:", re.IGNORECASE),
]

ERROR_PATTERNS = [
    re.compile(
        r"^\S+\s+\S+\s+\d+\s+\d+\s+E\s+",
        re.IGNORECASE,
    ),
    re.compile(r"\bERROR\s*:", re.IGNORECASE),
]


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

    crash_lines = _find_regex_matching_lines(
        lines,
        CRASH_PATTERNS,
    )

    exception_lines = _find_regex_matching_lines(
        lines,
        EXCEPTION_PATTERNS,
    )

    permission_denial_lines = _find_regex_matching_lines(
        lines,
        PERMISSION_DENIAL_PATTERNS,
    )

    network_lines = _find_regex_matching_lines(
        lines,
        NETWORK_PATTERNS,
    )

    webview_lines = _find_regex_matching_lines(
        lines,
        WEBVIEW_PATTERNS,
    )

    security_lines = _find_regex_matching_lines(
        lines,
        SECURITY_PATTERNS,
    )

    warning_lines = _find_regex_matching_lines(
        lines,
        WARNING_PATTERNS,
    )

    error_lines = _find_regex_matching_lines(
        lines,
        ERROR_PATTERNS,
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


def _find_regex_matching_lines(
    lines: list[str],
    patterns: list[re.Pattern[str]],
    limit: int = 50,
) -> list[str]:
    """
    Return log lines matching at least one precise regex pattern.
    """

    matches = []

    for line in lines:
        if any(pattern.search(line) for pattern in patterns):
            matches.append(line.strip())

        if len(matches) >= limit:
            break

    return matches