"""
AndroAI Sandbox - Backend Entry Point

This module creates the FastAPI application for the AndroAI Sandbox backend.

Current scope:
- Create the FastAPI app
- Add a root endpoint
- Add a health-check endpoint
- Register the APK upload router
- Register the report download router

APK upload processing logic will be implemented incrementally during Phase 5.
"""

from fastapi import FastAPI

from backend.report_handler import router as report_router
from backend.upload_handler import router as upload_router


app = FastAPI(
    title="AndroAI Sandbox API",
    description="Evidence-Based AI-Powered Android Malware Analysis Sandbox backend.",
    version="0.1.0",
)

# Register API routers
app.include_router(upload_router)
app.include_router(report_router)


@app.get("/")
def root() -> dict[str, str]:
    """
    Root endpoint used to verify that the backend server is running.
    """
    return {"message": "AndroAI Sandbox backend is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    """
    Health-check endpoint used for testing and monitoring.
    """
    return {
        "status": "ok",
        "service": "androai-backend",
    }