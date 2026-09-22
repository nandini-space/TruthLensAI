"""FastAPI application exposing the Module 1 detection pipeline."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.module2 import router as module2_router
from backend.detection.config import ApiConfig

from .routes.detection import router


def create_app(config: ApiConfig | None = None, *, service_name: str = "TruthLensAI Detection API") -> FastAPI:
    """Create the HTTP application without placing detection logic in routes."""
    settings = config or ApiConfig()
    app = FastAPI(
        title="TruthLensAI",
        version="1.0.0",
        description="TruthLensAI detection, threat intelligence, incident, and response API.",
    )
    app.state.service_name = service_name
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=["Content-Type"],
        )
    app.include_router(router)
    app.include_router(module2_router)
    return app


app = create_app(service_name="TruthLensAI")
