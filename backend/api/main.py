"""FastAPI application exposing the Module 1 detection pipeline."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.detection.config import ApiConfig

from .routes.detection import router


def create_app(config: ApiConfig | None = None) -> FastAPI:
    """Create the HTTP application without placing detection logic in routes."""
    settings = config or ApiConfig()
    app = FastAPI(
        title="TruthLensAI Detection API",
        version="1.0.0",
        description="HTTP access to the TruthLensAI Module 1 detection engine.",
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=["Content-Type"],
        )
    app.include_router(router)
    return app


app = create_app()
