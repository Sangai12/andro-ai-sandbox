"""
AndroAI Sandbox - Report Handler

Handles generated report access.

Phase 25.2, Phase 27, and Phase 40 scope:
- Serve generated HTML reports
- Serve generated PDF reports
- Serve generated JSON reports
- List available generated reports
- Keep report download logic separate from upload logic
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)

REPORT_DIRECTORY = Path("reports")
REPORT_DIRECTORY.mkdir(exist_ok=True)


@router.get("/list/all")
def list_reports() -> dict:
    """
    List all generated reports.
    """

    report_files = []

    for report_path in sorted(REPORT_DIRECTORY.iterdir()):
        if not report_path.is_file():
            continue

        if report_path.suffix not in [".html", ".pdf", ".json"]:
            continue

        report_files.append(
            {
                "filename": report_path.name,
                "path": str(report_path),
                "size": report_path.stat().st_size,
                "extension": report_path.suffix,
            }
        )

    return {
        "report_count": len(report_files),
        "reports": report_files,
    }


@router.get("/{filename}")
def download_report(filename: str):
    """
    Download or open a generated HTML, PDF, or JSON report.
    """

    if filename.endswith(".html"):
        media_type = "text/html"
    elif filename.endswith(".pdf"):
        media_type = "application/pdf"
    elif filename.endswith(".json"):
        media_type = "application/json"
    else:
        raise HTTPException(
            status_code=400,
            detail="Only HTML, PDF, and JSON reports can be downloaded.",
        )

    report_path = REPORT_DIRECTORY / filename

    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    return FileResponse(
        path=report_path,
        media_type=media_type,
        filename=filename,
    )