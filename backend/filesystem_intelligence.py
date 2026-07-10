"""
AndroAI Sandbox - Filesystem Intelligence

This module analyzes runtime filesystem evidence collected during
dynamic analysis.

Milestone 2 scope:
- Analyze filesystem-related runtime indicators
- Classify common Android filesystem locations
- Detect potential persistence locations
- Summarize filesystem activity
- Produce analyst-friendly filesystem intelligence
"""

from typing import Any


def analyze_filesystem_intelligence(
    runtime_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze runtime filesystem indicators.
    """

    indicators = runtime_analysis.get(
        "filesystem_indicators",
        [],
    )

    data_paths = []
    cache_paths = []
    files_paths = []
    databases = []
    shared_prefs = []
    downloads = []
    temporary = []
    other = []

    for indicator in indicators:
        text = str(indicator).lower()

        if "/databases/" in text:
            databases.append(indicator)

        elif "/shared_prefs/" in text:
            shared_prefs.append(indicator)

        elif "/cache/" in text:
            cache_paths.append(indicator)

        elif "/files/" in text:
            files_paths.append(indicator)

        elif "/download" in text:
            downloads.append(indicator)

        elif any(
            keyword in text
            for keyword in (
                "/tmp/",
                "/temp/",
                ".tmp",
                ".temp",
            )
        ):
            temporary.append(indicator)

        elif "/data/data/" in text:
            data_paths.append(indicator)

        else:
            other.append(indicator)

    return {
        "success": True,
        "total_filesystem_indicators": len(indicators),
        "data_directory_count": len(data_paths),
        "cache_directory_count": len(cache_paths),
        "files_directory_count": len(files_paths),
        "database_count": len(databases),
        "shared_preferences_count": len(shared_prefs),
        "download_count": len(downloads),
        "temporary_file_count": len(temporary),
        "other_count": len(other),
        "data_directories": data_paths[:20],
        "cache_directories": cache_paths[:20],
        "files_directories": files_paths[:20],
        "databases": databases[:20],
        "shared_preferences": shared_prefs[:20],
        "downloads": downloads[:20],
        "temporary_files": temporary[:20],
        "other": other[:20],
        "filesystem_flags": {
            "filesystem_activity_detected": len(indicators) > 0,
            "app_data_access_detected": (
                len(data_paths)
                + len(cache_paths)
                + len(files_paths)
                + len(databases)
                + len(shared_prefs)
            )
            > 0,
            "database_activity_detected": len(databases) > 0,
            "shared_preferences_detected": len(shared_prefs) > 0,
            "temporary_file_activity_detected": len(temporary) > 0,
        },
        "message": "Filesystem intelligence analyzed successfully.",
    }