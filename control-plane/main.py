"""Compatibility entry point for the Gavel control plane.

The canonical FastAPI application lives in ``api.main``. This module exists so
older invocations such as ``uvicorn main:app`` still run the same hardened app
that Docker, tests, and CI exercise.
"""

from api.main import app as app

if __name__ == "__main__":
    import os

    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info"),
    )
