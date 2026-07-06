# AndroAI Sandbox

Evidence-Based AI-Powered Android Malware Analysis Sandbox.

## Project Philosophy

**No conclusion without evidence.**

Every finding, warning, risk score, and report must be supported by technical evidence.

## Project Status

- ✅ Phase 1: Development Environment Setup
- ✅ Phase 2: Project Folder Structure
- ✅ Phase 3: Backend Foundation

## Backend Setup

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Run the backend:

```bash
uvicorn backend.main:app --reload
```

Open in your browser:

- http://127.0.0.1:8000
- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/docs

Run automated tests:

```bash
pytest
```
