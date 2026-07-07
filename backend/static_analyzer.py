"""
AndroAI Sandbox - Static Analyzer

This module performs static APK analysis.

Phase 6 scope:
- Load APK files
- Extract basic APK metadata
"""

from pathlib import Path
from typing import Any

from androguard.core.apk import APK


def extract_apk_metadata(apk_path: str | Path) -> dict[str, Any]:
    """
    Extract basic metadata from an APK file.

    Args:
        apk_path: Path to the APK file.

    Returns:
        Dictionary containing APK metadata.
    """
    apk_file = Path(apk_path)

    if not apk_file.exists():
        raise FileNotFoundError(f"APK file not found: {apk_file}")

    apk = APK(str(apk_file))

    return {
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
    }