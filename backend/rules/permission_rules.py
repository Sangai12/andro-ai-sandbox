"""
AndroAI Sandbox - Permission Rules

This module contains evidence-based permission detection rules.

Each rule describes:
- Unique identifier
- Human-readable title
- Severity
"""

PERMISSION_RULES = {
    "android.permission.CAMERA": {
        "id": "PERM_CAMERA",
        "title": "Camera Permission Requested",
        "severity": "medium",
    },
    "android.permission.RECORD_AUDIO": {
        "id": "PERM_RECORD_AUDIO",
        "title": "Microphone Permission Requested",
        "severity": "medium",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "id": "PERM_FINE_LOCATION",
        "title": "Precise Location Permission Requested",
        "severity": "high",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "id": "PERM_COARSE_LOCATION",
        "title": "Approximate Location Permission Requested",
        "severity": "medium",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "id": "PERM_BOOT_COMPLETED",
        "title": "Boot Persistence Permission Requested",
        "severity": "high",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "id": "PERM_QUERY_ALL_PACKAGES",
        "title": "Package Visibility Permission Requested",
        "severity": "high",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "id": "PERM_READ_EXTERNAL_STORAGE",
        "title": "External Storage Read Permission Requested",
        "severity": "medium",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "id": "PERM_WRITE_EXTERNAL_STORAGE",
        "title": "External Storage Write Permission Requested",
        "severity": "medium",
    },
    "android.permission.POST_NOTIFICATIONS": {
        "id": "PERM_POST_NOTIFICATIONS",
        "title": "Notification Permission Requested",
        "severity": "low",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "id": "PERM_FOREGROUND_SERVICE",
        "title": "Foreground Service Permission Requested",
        "severity": "medium",
    },
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": {
        "id": "PERM_FOREGROUND_SERVICE_DATA_SYNC",
        "title": "Data Sync Foreground Service Permission Requested",
        "severity": "medium",
    },
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK": {
        "id": "PERM_FOREGROUND_SERVICE_MEDIA_PLAYBACK",
        "title": "Media Playback Foreground Service Permission Requested",
        "severity": "low",
    },
}