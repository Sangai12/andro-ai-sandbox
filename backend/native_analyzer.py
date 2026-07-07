"""
AndroAI Sandbox - Native Analyzer

This module extracts native library information from APK files.

Phase 12 scope:
- Detect native .so libraries
- Extract native CPU architectures
- Prepare native evidence for future detection rules
"""

from typing import Any

from androguard.core.apk import APK


def extract_native_libraries(
    apk: APK,
) -> dict[str, Any]:
    """
    Extract native library paths and architectures from an APK.
    """

    native_libraries: list[str] = []
    native_architectures: set[str] = set()

    for apk_file in apk.get_files():
        if not apk_file.startswith("lib/"):
            continue

        if not apk_file.endswith(".so"):
            continue

        native_libraries.append(apk_file)

        parts = apk_file.split("/")

        if len(parts) >= 3:
            native_architectures.add(parts[1])

    return {
        "native_libraries": sorted(native_libraries),
        "native_library_count": len(native_libraries),
        "native_architectures": sorted(native_architectures),
    }