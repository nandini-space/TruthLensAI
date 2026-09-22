from fastapi import FastAPI

from backend.api.module2 import router as module2_router


app = FastAPI(title="TruthLensAI")
app.include_router(module2_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "TruthLensAI"}
