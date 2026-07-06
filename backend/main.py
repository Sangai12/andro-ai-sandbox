"""
AndroAI Sandbox - Backend Entry Point

This module creates the FastAPI application for the AndroAI Sandbox backend.

Phase 3 scope:
- Create the FastAPI app
- Add a root endpoint
- Add a health-check endpoint

No APK analysis, database logic, risk scoring, or AI logic is implemented in this phase.
"""

from fastapi import FastAPI


app = FastAPI(
    title="AndroAI Sandbox API",
    description="Evidence-Based AI-Powered Android Malware Analysis Sandbox backend.",
    version="0.1.0",
)


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
