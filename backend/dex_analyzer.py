"""
AndroAI Sandbox - DEX Analyzer

This module extracts DEX file information from APK files.

Phase 13 scope:
- Detect classes.dex files
- Count DEX files
- Prepare DEX evidence for future code analysis
"""

from typing import Any

from androguard.core.apk import APK


def extract_dex_metadata(
    apk: APK,
) -> dict[str, Any]:
    """
    Extract DEX file metadata from an APK.
    """

    dex_files: list[str] = []

    for apk_file in apk.get_files():
        if apk_file.endswith(".dex"):
            dex_files.append(apk_file)

    return {
        "dex_files": sorted(dex_files),
        "dex_file_count": len(dex_files),
    }