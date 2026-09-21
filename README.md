# TruthLensAI
AI-powered multimodal threat detection and response platform
# TruthLensAI

TruthLensAI is an AI-powered multimodal threat detection and response platform for assessing text, URLs/domains, images/screenshots, audio/voice, and video.

Its core workflow is:

**DETECT → EXPLAIN → ENRICH → INVESTIGATE → RESPOND**

This repository currently contains only the initial project structure, documentation, and a minimal backend health endpoint. Detection, intelligence integrations, orchestration, database schema, and user interfaces are intentionally not implemented yet.

## Project layout

- `backend/` — FastAPI service and future backend modules.
- `frontend/` — Reserved for the Next.js web security dashboard.
- `n8n/workflows/` — Reserved for n8n Cloud workflow definitions.
- `benchmark/` — Reserved for evaluation assets and benchmarks.
- `docs/` — Reserved for supporting project documentation.

## Backend health check

From the repository root, install FastAPI and an ASGI server, then run:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

`GET /health` returns:

```json
{"status":"ok","service":"TruthLensAI"}
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the intended system boundaries.
