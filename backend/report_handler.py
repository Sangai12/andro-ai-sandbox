"""
AndroAI Sandbox - Report Handler

Handles generated report access.

Phase 25.2 and Phase 27 scope:
- Serve generated HTML reports
- Serve generated PDF reports
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


@router.get("/{filename}")
def download_report(filename: str):
    """
    Download or open a generated HTML or PDF report.
    """

    if filename.endswith(".html"):
        media_type = "text/html"
    elif filename.endswith(".pdf"):
        media_type = "application/pdf"
    else:
        raise HTTPException(
            status_code=400,
            detail="Only HTML and PDF reports can be downloaded.",
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