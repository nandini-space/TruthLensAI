# Module 3C Telegram → Module 1 workflow

`truthlens_module_3c_mock.json` is the Task 3C-4 importable n8n workflow.
It receives a Telegram message, uses the existing Module 1 HTTP API for text
and URLs, converts its response to the Module 3C envelope, and sends a readable
Telegram reply. It never calls Module 2.

It is **not a production Telegram workflow**: it has no per-user/chat
conversation state or callback ownership validation, and supports only text and
URLs in real mode. See `docs/integration-audit.md` before activation.

```text
Telegram → n8n → Module 1 (/scan/text or /scan/url) → Module 3C envelope → Telegram
```

## Configuration and activation

1. Set these environment variables on the n8n process/container (not in the
   workflow export):

   ```text
   TRUTHLENSAI_BACKEND_URL=http://truthlensai-backend:8000
   TRUTHLENSAI_BACKEND_TIMEOUT_MS=30000
   TRUTHLENSAI_MOCK_MODE=false
   ```

   `TRUTHLENSAI_BACKEND_URL` is the base URL only—do not include a scan path.
   The n8n environment must permit `$env` access in expressions/Code nodes.

2. Import `truthlens_module_3c_mock.json` in n8n.
3. Create/select a Telegram credential for both Telegram nodes. Keep the bot
   token only in n8n credentials; no token or credential identifier is in the
   export.
4. Save and activate the workflow.

The Python polling bot and n8n's Telegram Trigger cannot consume updates for
the same bot at the same time. Stop polling first or use a separate test bot.

## Mock mode

Set `TRUTHLENSAI_MOCK_MODE=true` (the safe default when unset) to run the
previous offline mock workflow. No HTTP request is made in this mode and replies
are labelled `(MOCK)`. Set it to `false` to enable Module 1 calls without
editing workflow JavaScript.

## Connected API contracts

| Telegram type | Endpoint | Actual request body | Status |
|---|---|---|---|
| Text | `POST /scan/text` | `{ "text": "…" }` | Connected |
| URL | `POST /scan/url` | `{ "url": "https://…" }` | Connected |
| Image | — | — | Recognized; not connected |
| Audio | — | — | Recognized; not connected |
| Video | — | — | Recognized; not connected |

The real response maps Module 1 `scan_id`, `input_type`, `risk_score`,
`severity`, `threat_type`, `confidence`, `signals` (`code`, `description`,
`source`), `explanation`, and `recommendation` to the documented Module 3C
normalized envelope. `entities`, `metadata`, and `created_at` are not exposed
by this initial Telegram response because they are not fields in that envelope.
Threat intelligence, incidents, actions, and Module 2 are deliberately left
unavailable.

## Result actions (Task 3C-5)

Successful scan replies include inline WHY_SUSPICIOUS, WHAT_TO_DO, and
FULL_REPORT buttons. Callback data is ACTION:request_id; the UUID fits
Telegram's callback-data limit and is never derived from visible text.

n8n stores only normalized source and scan fields in workflow static data for
24 hours, keyed by request_id. This is n8n-managed persistent workflow state,
not a Python in-memory dictionary or a new database. Expired, malformed, or
unknown callbacks return a safe “run a new scan” message. Callback presses do
not call Module 1 again and never call Module 2.

Why suspicious? renders stored signals and explanation. What should I do?
renders the stored recommendation (or a cautious fallback if absent). Full
report always states that no report is available; no report is fabricated. A
future Module 2 integration can replace these context-only handlers while
retaining the same Telegram callback identifiers and UI.

## Module 2 investigation boundary (Task 3C-6)

Inspection confirms that the existing endpoint is POST /api/module2/investigate.
It accepts backend.models.schemas.ScanResult, not the Module 1 HTTP
backend.detection.schemas.ScanResult stored by this workflow. The canonical
request requires modality, timestamp, non-null risk score and confidence,
DetectionSignal name/value/source, extracted_entities, provenance, and
input_reference. Those fields do not map cleanly from the Module 1 HTTP result.

The endpoint returns a Module2Result containing scan_result, indicators,
provider_results, threat_intelligence, enriched_threat_result, evidence_pack,
incident, forensic_report, stix_bundle, response_decisions, and action_records.
Its documented errors are 409, 422, 500, and 503. Retrieval exists at GET
/api/module2/investigations/{scan_id}, with 404 and 503 responses.

No Module 2 call is safe until Module 1 or Module 2 supplies a documented
server-side canonicalization/handoff endpoint. Module 3C must not construct
that canonical request by guessing mappings. A future configured
TRUTHLENSAI_MODULE2_URL is therefore intentionally not consumed by the current
workflow.

## Error behavior

Empty input and unsupported real-mode media get safe user-facing errors.
HTTP 400/422, connection failure/timeout, HTTP 500, and invalid Module 1
responses are normalized to a safe error envelope; raw backend detail and stack
traces are never sent to Telegram. n8n retains execution details for operators.

## Testing

Offline checks require neither Telegram credentials nor a live backend:

```bash
python -m unittest tests.test_telegram_bot tests.test_module3c_n8n_workflow
```

For a manual integration test, run the local API (for example,
`uvicorn backend.main:app --host 0.0.0.0 --port 8000`), set the variables
above with mock mode false, then activate the workflow and send a normal text
message and a complete HTTP(S) URL. Confirm that each result is formatted in
Telegram and that no `/api/module2` request appears in the n8n execution.

| Case | Automated coverage | Manual check |
|---|---|---|
| TC-01–TC-04 | Endpoint/path/body and formatting structure | Send text and URL |
| TC-05–TC-09 | Safe status/error/invalid-response paths | Stop or misconfigure backend |
| TC-10–TC-12 | No Module 2/secrets; mock branch retained | Inspect execution and toggle mode |
| TC-13–TC-14 | Python Telegram and workflow suites | Not required |
