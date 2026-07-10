"""
Unit tests for AndroAI Sandbox dynamic runner helpers.
"""

from backend.dynamic_runner import (
    _filter_logcat_lines_by_package,
    _filter_logcat_lines_by_pid,
)


def test_filter_logcat_lines_by_pid_keeps_target_processes():
    lines = [
        "07-10 16:04:37.860 22786 22846 E Firefox: target line",
        "07-10 16:04:37.861 22786 22846 I Firefox: second target line",
        "07-10 16:04:37.862 634 655 W System: unrelated line",
        "07-10 16:04:37.863 23039 23050 I FirefoxTab: child process line",
    ]

    result = _filter_logcat_lines_by_pid(
        lines=lines,
        package_pids={"22786", "23039"},
    )

    assert result == [
        "07-10 16:04:37.860 22786 22846 E Firefox: target line",
        "07-10 16:04:37.861 22786 22846 I Firefox: second target line",
        "07-10 16:04:37.863 23039 23050 I FirefoxTab: child process line",
    ]


def test_filter_logcat_lines_by_pid_keeps_stack_trace_continuations():
    lines = [
        (
            "07-10 16:04:38.974 22786 22991 E Firefox: "
            "java.io.IOException"
        ),
        "    at org.mozilla.example.Client.fetch(Client.kt:10)",
        "Caused by: java.net.UnknownHostException",
        "07-10 16:04:38.975 634 655 W System: unrelated line",
    ]

    result = _filter_logcat_lines_by_pid(
        lines=lines,
        package_pids={"22786"},
    )

    assert result == [
        (
            "07-10 16:04:38.974 22786 22991 E Firefox: "
            "java.io.IOException"
        ),
        "    at org.mozilla.example.Client.fetch(Client.kt:10)",
    ]


def test_filter_logcat_lines_by_pid_excludes_unrelated_system_logs():
    lines = [
        "07-10 16:04:43.172 634 1332 W BinderNative: system exception",
        "07-10 16:04:38.774 174 182 E lowmemorykiller: system error",
        "07-10 16:04:38.902 22786 22826 I Firefox: app event",
    ]

    result = _filter_logcat_lines_by_pid(
        lines=lines,
        package_pids={"22786"},
    )

    assert result == [
        "07-10 16:04:38.902 22786 22826 I Firefox: app event",
    ]


def test_filter_logcat_lines_by_package_uses_package_name_fallback():
    lines = [
        (
            "07-10 16:04:37.798 634 655 V WindowManager: "
            "cmp=org.mozilla.firefox/.App"
        ),
        (
            "07-10 16:04:37.799 634 655 V WindowManager: "
            "cmp=com.example.other/.MainActivity"
        ),
        (
            "07-10 16:04:37.800 22786 22846 I Firefox: "
            "package=org.mozilla.firefox"
        ),
    ]

    result = _filter_logcat_lines_by_package(
        lines=lines,
        package_name="org.mozilla.firefox",
    )

    assert result == [
        (
            "07-10 16:04:37.798 634 655 V WindowManager: "
            "cmp=org.mozilla.firefox/.App"
        ),
        (
            "07-10 16:04:37.800 22786 22846 I Firefox: "
            "package=org.mozilla.firefox"
        ),
    ]


def test_filter_logcat_lines_by_package_is_case_insensitive():
    lines = [
        (
            "07-10 16:04:37.800 22786 22846 I Firefox: "
            "ORG.MOZILLA.FIREFOX started"
        ),
    ]

    result = _filter_logcat_lines_by_package(
        lines=lines,
        package_name="org.mozilla.firefox",
    )

    assert result == lines