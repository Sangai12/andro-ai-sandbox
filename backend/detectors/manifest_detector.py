"""
AndroAI Sandbox - Manifest Detector

This module evaluates AndroidManifest.xml attributes
and returns evidence-based findings.
"""

from typing import Any


def _add_finding(
    findings: list[dict[str, str]],
    finding_id: str,
    title: str,
    severity: str,
    evidence_type: str,
    evidence: str,
) -> None:
    findings.append(
        {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "evidence_type": evidence_type,
            "evidence": evidence,
        }
    )


def detect_manifest_findings(apk: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    permissions = apk.get_permissions()

    permission_checks = {
        "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": {
            "id": "MANIFEST_FOREGROUND_SERVICE_SPECIAL_USE",
            "title": "Foreground Service Special Use Permission Requested",
            "severity": "medium",
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "id": "MANIFEST_SYSTEM_ALERT_WINDOW",
            "title": "Overlay Permission Requested",
            "severity": "high",
        },
        "android.permission.ACCESS_BACKGROUND_LOCATION": {
            "id": "MANIFEST_BACKGROUND_LOCATION",
            "title": "Background Location Permission Requested",
            "severity": "high",
        },
        "android.permission.REQUEST_INSTALL_PACKAGES": {
            "id": "MANIFEST_REQUEST_INSTALL_PACKAGES",
            "title": "Install Unknown Apps Permission Requested",
            "severity": "high",
        },
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
            "id": "MANIFEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "title": "Ignore Battery Optimization Permission Requested",
            "severity": "high",
        },
        "android.permission.PACKAGE_USAGE_STATS": {
            "id": "MANIFEST_PACKAGE_USAGE_STATS",
            "title": "Usage Stats Permission Requested",
            "severity": "high",
        },
    }

    for permission, rule in permission_checks.items():
        if permission in permissions:
            _add_finding(
                findings=findings,
                finding_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                evidence_type="manifest_permission",
                evidence=permission,
            )

    debuggable = apk.get_attribute_value("application", "debuggable")

    if debuggable == "true":
        _add_finding(
            findings=findings,
            finding_id="MANIFEST_DEBUGGABLE",
            title="Application Debuggable Flag Enabled",
            severity="high",
            evidence_type="manifest_attribute",
            evidence="android:debuggable=true",
        )

    allow_backup = apk.get_attribute_value("application", "allowBackup")

    if allow_backup == "true":
        _add_finding(
            findings=findings,
            finding_id="MANIFEST_ALLOW_BACKUP",
            title="Application Backup Enabled",
            severity="medium",
            evidence_type="manifest_attribute",
            evidence="android:allowBackup=true",
        )

    for activity in apk.get_activities():
        exported = apk.get_attribute_value("activity", "exported", name=activity)

        if exported == "true":
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_EXPORTED_ACTIVITY",
                title="Exported Activity Detected",
                severity="medium",
                evidence_type="manifest_component",
                evidence=f"activity={activity}; android:exported=true",
            )

    for service in apk.get_services():
        exported = apk.get_attribute_value("service", "exported", name=service)
        service_permission = apk.get_attribute_value("service", "permission", name=service)
        service_actions = apk.get_intent_filters("service", service).get("action", [])

        if exported == "true":
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_EXPORTED_SERVICE",
                title="Exported Service Detected",
                severity="high",
                evidence_type="manifest_component",
                evidence=f"service={service}; android:exported=true",
            )

        if (
            service_permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
            or "android.accessibilityservice.AccessibilityService" in service_actions
        ):
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_ACCESSIBILITY_SERVICE",
                title="Accessibility Service Detected",
                severity="high",
                evidence_type="manifest_service",
                evidence=f"service={service}; accessibility_service=true",
            )

        if (
            service_permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
            or "android.service.notification.NotificationListenerService" in service_actions
        ):
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_NOTIFICATION_LISTENER",
                title="Notification Listener Service Detected",
                severity="high",
                evidence_type="manifest_service",
                evidence=f"service={service}; notification_listener=true",
            )

        if "android.net.VpnService" in service_actions:
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_VPN_SERVICE",
                title="VPN Service Detected",
                severity="high",
                evidence_type="manifest_service",
                evidence=f"service={service}; action=android.net.VpnService",
            )

    for receiver in apk.get_receivers():
        exported = apk.get_attribute_value("receiver", "exported", name=receiver)
        receiver_actions = apk.get_intent_filters("receiver", receiver).get("action", [])

        if exported == "true":
            _add_finding(
                findings=findings,
                finding_id="MANIFEST_EXPORTED_RECEIVER",
                title="Exported Receiver Detected",
                severity="high",
                evidence_type="manifest_component",
                evidence=f"receiver={receiver}; android:exported=true",
            )

        receiver_action_checks = {
            "android.intent.action.BOOT_COMPLETED": {
                "id": "MANIFEST_BOOT_RECEIVER",
                "title": "Boot Completed Receiver Detected",
                "severity": "high",
            },
            "android.intent.action.LOCKED_BOOT_COMPLETED": {
                "id": "MANIFEST_LOCKED_BOOT_RECEIVER",
                "title": "Locked Boot Receiver Detected",
                "severity": "high",
            },
            "android.app.action.DEVICE_ADMIN_ENABLED": {
                "id": "MANIFEST_DEVICE_ADMIN",
                "title": "Device Administrator Receiver Detected",
                "severity": "high",
            },
            "android.provider.Telephony.SMS_RECEIVED": {
                "id": "MANIFEST_SMS_RECEIVER",
                "title": "SMS Receiver Detected",
                "severity": "high",
            },
            "android.intent.action.PACKAGE_ADDED": {
                "id": "MANIFEST_PACKAGE_ADDED_RECEIVER",
                "title": "Package Added Receiver Detected",
                "severity": "medium",
            },
            "android.intent.action.PACKAGE_REMOVED": {
                "id": "MANIFEST_PACKAGE_REMOVED_RECEIVER",
                "title": "Package Removed Receiver Detected",
                "severity": "medium",
            },
        }

        for action, rule in receiver_action_checks.items():
            if action in receiver_actions:
                _add_finding(
                    findings=findings,
                    finding_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    evidence_type="manifest_intent_filter",
                    evidence=f"receiver={receiver}; action={action}",
                )

    return findings