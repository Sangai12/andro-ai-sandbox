"""
AndroAI Sandbox - Upload Module

Handles APK uploads.

Phase 5, Phase 6, and Phase 25 scope:
- Receive APK files
- Validate APK extension
- Generate file hashes
- Save uploaded APK using SHA-256 filename
- Extract APK metadata and analysis report
- Generate HTML analysis report
"""

from pathlib import Path
import hashlib

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.html_report_generator import generate_html_report
from backend.static_analyzer import extract_apk_metadata

router = APIRouter(
    prefix="/upload",
    tags=["APK Upload"],
)

UPLOAD_DIRECTORY = Path("uploads")
UPLOAD_DIRECTORY.mkdir(exist_ok=True)

REPORT_DIRECTORY = Path("reports")
REPORT_DIRECTORY.mkdir(exist_ok=True)


@router.post("/")
async def upload_apk(file: UploadFile = File(...)):
    """
    Upload an APK file, generate evidence metadata, extract APK metadata,
    and generate an HTML report.
    """

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only APK files are allowed.",
        )

    contents = await file.read()

    md5_hash = hashlib.md5(contents).hexdigest()
    sha1_hash = hashlib.sha1(contents).hexdigest()
    sha256_hash = hashlib.sha256(contents).hexdigest()

    stored_filename = f"{sha256_hash}.apk"
    destination = UPLOAD_DIRECTORY / stored_filename

    with open(destination, "wb") as apk_file:
        apk_file.write(contents)

    metadata = extract_apk_metadata(destination)

    html_report = generate_html_report(metadata)
    html_report_filename = f"{sha256_hash}.html"
    html_report_path = REPORT_DIRECTORY / html_report_filename

    with open(html_report_path, "w", encoding="utf-8") as report_file:
        report_file.write(html_report)

    return {
        "original_filename": file.filename,
        "stored_filename": stored_filename,
        "size": len(contents),
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "saved_to": str(destination),
        "html_report": str(html_report_path),
        "status": "uploaded",
        "metadata": metadata,
    }