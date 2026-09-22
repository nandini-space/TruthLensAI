# TruthLensAI
AI-powered multimodal threat detection and response platform
# TruthLensAI

TruthLensAI is an AI-powered multimodal threat detection and response platform for assessing text, URLs/domains, images/screenshots, audio/voice, and video.

Its core workflow is:

**DETECT → EXPLAIN → ENRICH → INVESTIGATE → RESPOND**

The backend implements the canonical `ScanResult` handoff, deterministic
multimodal detection boundaries, and Module 2 investigation: IOC extraction,
provider-neutral intelligence aggregation, evidence, incidents, forensic
reports, STIX export, dry-run response records, and optional Supabase-backed
investigation persistence. The frontend and n8n workflow directories remain
placeholders.

## Project layout

- `backend/` — FastAPI service and future backend modules.
- `frontend/` — Reserved for the Next.js web security dashboard.
- `n8n/workflows/` — Reserved for n8n Cloud workflow definitions.
- `benchmark/` — Reserved for evaluation assets and benchmarks.
- `docs/` — Reserved for supporting project documentation.

## Local backend setup

From the repository root, create and activate a Python virtual environment,
then install the declared dependencies:

```bash
python -m venv .venv
# Activate .venv using your platform's standard command.
pip install -r requirements.txt
python -m unittest discover
uvicorn backend.main:app --reload
```

`GET /health` returns:

```json
{"status":"ok","service":"TruthLensAI"}
```

Tests run fully offline and do not require Supabase or VirusTotal credentials.
Copy `.env.example` only when configuring optional runtime integrations; values
are read from environment variables and must not be committed.

The current settings layer recognizes `APP_ENV`, `APP_HOST`, `APP_PORT`,
`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and
`VIRUSTOTAL_API_KEY`. The service-role key is used only by the optional Supabase
repository; no API endpoint returns configuration values.

## Integration map

```text
Web dashboard -> FastAPI /scan/* -> Module 1 detection -> displayed HTTP result
n8n Telegram workflow -> FastAPI /scan/* -> normalized Telegram response
Web investigation dashboard -> FastAPI /api/module2/investigations -> Module 2 snapshots
```

The web scan form calls existing Module 1 routes. n8n is the production
Telegram update owner; `module_3c/telegram_bot` is prototype/reference only.

**Module 2 integration blocked:** Module 1 HTTP responses are not canonical
`backend.models.schemas.ScanResult` values. Required provenance and safe input
reference fields are not present, so the server intentionally does not invent a
converter. A canonical upstream handoff is required before a scan result can
start Module 2. `GET /ready` reports safe component/configuration status.

See [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md) for implemented
controls and operating limitations.

## Module 2 API

- `POST /api/module2/investigate` runs Module 2 for a canonical `ScanResult`.
- `GET /api/module2/investigations/{scan_id}` retrieves one persisted result.
- `GET /api/module2/investigations?limit=20&offset=0` returns read-only history.

Persistence is enabled only when both `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` are configured and the migrations in
`supabase/migrations/` have been applied. Both retrieval endpoints are
read-only; response actions remain dry-run only. See
[Module 2 contracts](docs/module2-contracts.md) and
[ScanResult contract](docs/scan-result-contract.md) for API and data details.

## Local image OCR

Image detection accepts local PNG, JPEG, and WEBP file paths. It uses Pillow plus the `pytesseract` Python wrapper. Running actual OCR also requires the local [Tesseract OCR executable](https://github.com/tesseract-ocr/tesseract); when it is unavailable, image scans return a typed unassessed result instead of inferred text.
