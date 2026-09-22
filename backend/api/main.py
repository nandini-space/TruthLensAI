"""FastAPI application exposing the Module 1 detection pipeline."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse

from backend.api.module2 import router as module2_router
from backend.config import Settings
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
    app.state.rate_limit_per_minute = settings.rate_limit_per_minute
    if settings.api_key:
        @app.middleware("http")
        async def require_service_key(request: Request, call_next):
            if request.url.path != "/health" and request.headers.get("X-TruthLens-API-Key") != settings.api_key:
                return JSONResponse(status_code=401, content={"detail": "Authentication required."})
            return await call_next(request)
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

    @app.get("/ready", tags=["health"], summary="Safe integration readiness")
    def readiness() -> dict[str, object]:
        configured = Settings.from_environment()
        database_configured = bool(configured.supabase_url and configured.supabase_service_role_key)
        return {"status": "ready", "api": "available", "module1": "available", "module2": "available", "database": "configured" if database_configured else "unconfigured"}
    return app


app = create_app(service_name="TruthLensAI")
