"""
AndroAI Sandbox - Upload Module

Handles APK uploads.

Phase 5 scope:
- Receive APK files
- Validate APK extension
- Generate file hashes
- Save uploaded APK using SHA-256 filename
"""

from pathlib import Path
import hashlib

from fastapi import APIRouter, File, HTTPException, UploadFile

router = APIRouter(
    prefix="/upload",
    tags=["APK Upload"],
)

UPLOAD_DIRECTORY = Path("uploads")
UPLOAD_DIRECTORY.mkdir(exist_ok=True)


@router.post("/")
async def upload_apk(file: UploadFile = File(...)):
    """
    Upload an APK file and generate evidence metadata.
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

    return {
        "original_filename": file.filename,
        "stored_filename": stored_filename,
        "size": len(contents),
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "saved_to": str(destination),
        "status": "uploaded",
    }