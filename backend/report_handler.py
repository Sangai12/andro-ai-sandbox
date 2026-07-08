"""
AndroAI Sandbox - Report Handler

Handles generated report access.

Phase 25.2 scope:
- Serve generated HTML reports
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
    Download or open a generated HTML report.
    """

    if not filename.endswith(".html"):
        raise HTTPException(
            status_code=400,
            detail="Only HTML reports can be downloaded.",
        )

    report_path = REPORT_DIRECTORY / filename

    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    return FileResponse(
        path=report_path,
        media_type="text/html",
        filename=filename,
    )