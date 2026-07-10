"""
Tests for the AndroAI Sandbox runtime log analyzer.

These tests verify that runtime evidence is extracted correctly and
that common Android framework noise does not produce false positives.
"""

from pathlib import Path

from backend.runtime_log_analyzer import analyze_runtime_log


def _write_log(tmp_path: Path, lines: list[str]) -> Path:
    log_path = tmp_path / "runtime.log"
    log_path.write_text("\n".join(lines), encoding="utf-8")
    return log_path


def test_detects_runtime_exception(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "E AndroidRuntime: FATAL EXCEPTION: main",
            "java.lang.NullPointerException",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["success"] is True
    assert result["crash_count"] == 1
    assert result["exception_count"] >= 1
    assert result["behavior_summary"]["crash_detected"] is True
    assert result["behavior_summary"]["exception_detected"] is True


def test_detects_permission_denial(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "Permission Denial: opening provider",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["permission_denial_count"] == 1
    assert (
        result["behavior_summary"]["permission_denial_detected"]
        is True
    )


def test_detects_network_activity(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "Connecting to https://example.com/api",
            "TLS handshake complete",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["network_indicator_count"] >= 2
    assert (
        result["behavior_summary"]["network_activity_detected"]
        is True
    )


def test_detects_webview_activity(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "WebView initialized",
            "console.error: javascript",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["webview_indicator_count"] >= 1
    assert (
        result["behavior_summary"]["webview_activity_detected"]
        is True
    )


def test_detects_security_events(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "SELinux: avc: denied",
            "frida detected",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["security_indicator_count"] >= 2
    assert (
        result["behavior_summary"]["security_event_detected"]
        is True
    )


def test_ignores_root_task_false_positive(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "topRootTask=Task{123}",
            "rootOfTask=true",
            "mPreferredTopFocusableRootTask",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["security_indicator_count"] == 0
    assert (
        result["behavior_summary"]["security_event_detected"]
        is False
    )


def test_ignores_error_callback_false_positive(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "errorCallbackToken=null",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["error_count"] == 0
    assert result["behavior_summary"]["error_detected"] is False


def test_ignores_transition_request_connect_false_positive(tmp_path):
    log = _write_log(
        tmp_path,
        [
            "TransitionRequestInfo created",
            "connectFlags=0x01",
        ],
    )

    result = analyze_runtime_log(log)

    assert result["network_indicator_count"] == 0
    assert (
        result["behavior_summary"]["network_activity_detected"]
        is False
    )


def test_empty_log(tmp_path):
    log = _write_log(tmp_path, [])

    result = analyze_runtime_log(log)

    assert result["success"] is True
    assert result["line_count"] == 0
    assert result["behavior_summary"]["detected_behavior_count"] == 0