"""
Unit tests for AndroAI Sandbox runtime intelligence modules.
"""

from backend.behavior_confidence import calculate_behavior_confidence
from backend.filesystem_intelligence import analyze_filesystem_intelligence
from backend.intent_intelligence import analyze_intent_intelligence
from backend.network_intelligence import analyze_network_intelligence
from backend.persistence_intelligence import (
    analyze_persistence_intelligence,
)
from backend.process_intelligence import analyze_process_intelligence
from backend.service_intelligence import analyze_service_intelligence


def test_process_intelligence_detects_primary_and_child_processes():
    behavior_analysis = {
        "package_name": "com.example.app",
        "processes": [
            (
                "u0_a123 2100 500 123456 45678 0 0 S "
                "com.example.app"
            ),
            (
                "u0_a123 2101 2100 123456 45678 0 0 S "
                "com.example.app:remote"
            ),
        ],
    }

    result = analyze_process_intelligence(behavior_analysis)

    assert result["success"] is True
    assert result["process_count"] == 2
    assert result["unique_process_count"] == 2
    assert result["primary_process"]["name"] == "com.example.app"
    assert result["child_process_count"] == 1
    assert result["process_flags"]["app_process_running"] is True
    assert result["process_flags"]["multiple_processes_detected"] is True
    assert result["process_flags"]["child_processes_detected"] is True


def test_process_intelligence_handles_no_processes():
    behavior_analysis = {
        "package_name": "com.example.app",
        "processes": [],
    }

    result = analyze_process_intelligence(behavior_analysis)

    assert result["success"] is True
    assert result["process_count"] == 0
    assert result["primary_process"] == {}
    assert result["child_process_count"] == 0
    assert result["process_flags"]["app_process_running"] is False


def test_service_intelligence_detects_foreground_service():
    behavior_analysis = {
        "package_name": "com.example.app",
        "running_services": [
            (
                "ServiceRecord{12345 u0 "
                "com.example.app/.SyncService foreground}"
            ),
            (
                "ServiceRecord{67890 u0 "
                "com.example.app/.WorkerService background}"
            ),
        ],
    }

    result = analyze_service_intelligence(behavior_analysis)

    assert result["success"] is True
    assert result["service_count"] == 2
    assert result["unique_service_count"] == 2
    assert result["foreground_service_indicator_count"] == 1
    assert result["background_service_indicator_count"] == 1
    assert result["service_flags"]["services_running"] is True
    assert result["service_flags"]["multiple_services_detected"] is True
    assert (
        result["service_flags"][
            "foreground_service_indicator_detected"
        ]
        is True
    )


def test_network_intelligence_classifies_indicators():
    runtime_analysis = {
        "network_indicators": [
            "Connecting to https://api.example.com/data",
            "HTTP request sent to http://example.org",
            "DNS lookup for suspicious.example",
            "Socket connection opened",
            "TLS certificate validation completed",
            "Unknown network operation",
        ],
    }

    result = analyze_network_intelligence(runtime_analysis)

    assert result["success"] is True
    assert result["total_network_indicators"] == 6
    assert result["https_count"] == 1
    assert result["http_count"] == 1
    assert result["dns_count"] == 1
    assert result["socket_count"] == 1
    assert result["ssl_tls_count"] == 1
    assert result["other_count"] == 1
    assert result["network_flags"]["network_activity_detected"] is True
    assert result["network_flags"]["encrypted_traffic_detected"] is True
    assert result["network_flags"]["dns_activity_detected"] is True
    assert result["network_flags"]["socket_activity_detected"] is True


def test_filesystem_intelligence_classifies_paths():
    runtime_analysis = {
        "filesystem_indicators": [
            "/data/data/com.example.app/config.json",
            "/data/data/com.example.app/cache/session.tmp",
            "/data/data/com.example.app/files/payload.dex",
            "/data/data/com.example.app/databases/app.db",
            "/data/data/com.example.app/shared_prefs/config.xml",
            "/sdcard/Download/update.apk",
            "/tmp/runtime.temp",
            "/storage/emulated/0/unknown.bin",
        ],
    }

    result = analyze_filesystem_intelligence(runtime_analysis)

    assert result["success"] is True
    assert result["total_filesystem_indicators"] == 8
    assert result["data_directory_count"] >= 1
    assert result["database_count"] == 1
    assert result["shared_preferences_count"] == 1
    assert result["download_count"] == 1
    assert result["temporary_file_count"] == 1
    assert (
        result["filesystem_flags"]["filesystem_activity_detected"]
        is True
    )
    assert (
        result["filesystem_flags"]["database_activity_detected"]
        is True
    )
    assert (
        result["filesystem_flags"]["shared_preferences_detected"]
        is True
    )


def test_intent_intelligence_detects_boot_and_sms_events():
    runtime_analysis = {
        "security_indicators": [
            "Broadcast received: android.intent.action.BOOT_COMPLETED",
            "Receiver handled android.provider.Telephony.SMS_RECEIVED",
        ],
        "network_indicators": [
            "CONNECTIVITY_CHANGE broadcast observed",
        ],
        "warnings": [],
        "errors": [],
        "exceptions": [],
    }

    result = analyze_intent_intelligence(runtime_analysis)

    assert result["success"] is True
    assert result["total_intent_indicators"] == 3
    assert result["boot_event_count"] == 1
    assert result["sms_event_count"] == 1
    assert result["connectivity_event_count"] == 1
    assert result["intent_flags"]["intent_activity_detected"] is True
    assert result["intent_flags"]["boot_related_event_detected"] is True
    assert result["intent_flags"]["sms_event_detected"] is True
    assert result["intent_flags"]["connectivity_event_detected"] is True


def test_persistence_intelligence_ignores_active_process_alone():
    result = analyze_persistence_intelligence(
        process_intelligence={
            "process_flags": {
                "app_process_running": True,
            },
        },
        service_intelligence={
            "service_flags": {
                "services_running": False,
            },
        },
        filesystem_intelligence={
            "filesystem_flags": {
                "shared_preferences_detected": False,
                "database_activity_detected": False,
            },
        },
        intent_intelligence={
            "intent_flags": {
                "boot_related_event_detected": False,
            },
        },
    )

    assert result["success"] is True
    assert result["persistence_indicator_count"] == 0
    assert result["overall_confidence"] == "none"
    assert (
        result["persistence_flags"]["possible_persistence_detected"]
        is False
    )
    assert (
        result["persistence_flags"]["active_process_observed"]
        is True
    )
    assert (
        result["persistence_flags"]["process_persistence_indicator"]
        is False
    )


def test_persistence_intelligence_ignores_process_and_service_without_storage():
    result = analyze_persistence_intelligence(
        process_intelligence={
            "process_flags": {
                "app_process_running": True,
            },
        },
        service_intelligence={
            "service_flags": {
                "services_running": True,
            },
        },
        filesystem_intelligence={
            "filesystem_flags": {
                "shared_preferences_detected": False,
                "database_activity_detected": False,
            },
        },
        intent_intelligence={
            "intent_flags": {
                "boot_related_event_detected": False,
            },
        },
    )

    assert result["success"] is True
    assert result["persistence_indicator_count"] == 0
    assert result["overall_confidence"] == "none"
    assert (
        result["persistence_flags"]["possible_persistence_detected"]
        is False
    )


def test_persistence_intelligence_detects_boot_event():
    result = analyze_persistence_intelligence(
        process_intelligence={
            "process_flags": {
                "app_process_running": False,
            },
        },
        service_intelligence={
            "service_flags": {
                "services_running": False,
            },
        },
        filesystem_intelligence={
            "filesystem_flags": {
                "shared_preferences_detected": False,
                "database_activity_detected": False,
            },
        },
        intent_intelligence={
            "intent_flags": {
                "boot_related_event_detected": True,
            },
        },
    )

    assert result["success"] is True
    assert result["persistence_indicator_count"] == 1
    assert result["overall_confidence"] == "high"
    assert (
        result["persistence_flags"]["possible_persistence_detected"]
        is True
    )
    assert (
        result["persistence_flags"]["boot_persistence_indicator"]
        is True
    )


def test_persistence_intelligence_requires_correlated_runtime_and_storage():
    result = analyze_persistence_intelligence(
        process_intelligence={
            "process_flags": {
                "app_process_running": True,
            },
        },
        service_intelligence={
            "service_flags": {
                "services_running": True,
            },
        },
        filesystem_intelligence={
            "filesystem_flags": {
                "shared_preferences_detected": True,
                "database_activity_detected": False,
            },
        },
        intent_intelligence={
            "intent_flags": {
                "boot_related_event_detected": False,
            },
        },
    )

    assert result["success"] is True
    assert result["persistence_indicator_count"] == 2
    assert result["overall_confidence"] == "medium"
    assert (
        result["persistence_flags"]["possible_persistence_detected"]
        is True
    )
    assert (
        result["persistence_flags"]["service_persistence_indicator"]
        is True
    )
    assert (
        result["persistence_flags"]["process_persistence_indicator"]
        is True
    )
    assert (
        result["persistence_flags"][
            "state_storage_supporting_indicator"
        ]
        is True
    )


def test_behavior_confidence_uses_all_intelligence_sources():
    process_intelligence = {
        "process_count": 2,
        "child_process_count": 1,
        "process_flags": {
            "app_process_running": True,
            "multiple_processes_detected": True,
            "child_processes_detected": True,
        },
    }

    service_intelligence = {
        "service_count": 1,
        "service_flags": {
            "services_running": True,
            "foreground_service_indicator_detected": True,
        },
    }

    network_intelligence = {
        "total_network_indicators": 2,
        "network_flags": {
            "network_activity_detected": True,
            "encrypted_traffic_detected": True,
            "dns_activity_detected": False,
            "socket_activity_detected": False,
        },
    }

    filesystem_intelligence = {
        "total_filesystem_indicators": 1,
        "filesystem_flags": {
            "filesystem_activity_detected": True,
            "database_activity_detected": True,
            "shared_preferences_detected": False,
            "temporary_file_activity_detected": False,
        },
    }

    intent_intelligence = {
        "total_intent_indicators": 1,
        "intent_flags": {
            "intent_activity_detected": True,
            "boot_related_event_detected": True,
            "sms_event_detected": False,
            "phone_event_detected": False,
        },
    }

    persistence_intelligence = {
        "persistence_indicator_count": 3,
        "overall_confidence": "high",
        "persistence_flags": {
            "possible_persistence_detected": True,
        },
    }

    result = calculate_behavior_confidence(
        process_intelligence=process_intelligence,
        service_intelligence=service_intelligence,
        network_intelligence=network_intelligence,
        filesystem_intelligence=filesystem_intelligence,
        intent_intelligence=intent_intelligence,
        persistence_intelligence=persistence_intelligence,
    )

    assert result["success"] is True
    assert result["behavior_confidence_count"] == 6
    assert result["confidence_summary"]["high"] == 5
    assert result["confidence_summary"]["medium"] == 1
    assert result["confidence_summary"]["low"] == 0
    assert result["overall_behavior_confidence"] == "high"