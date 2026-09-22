# Integration audit

## Confirmed boundaries

```text
Module 3A browser -> FastAPI /scan/* -> backend.detection
Module 3B browser -> FastAPI /api/module2/investigations -> backend.module2
n8n workflow -> FastAPI /scan/text or /scan/url -> Telegram response
```

Module 3 does not import Module 1 or Module 2 Python implementation modules.
The Python Telegram bot is an isolated polling prototype; n8n owns production
Telegram updates and they must never use the same token concurrently.

## Module 2 integration blocker

**File:** `backend/detection/schemas.py` and `backend/models/schemas.py`  
**Component:** Module 1 HTTP to Module 2 handoff  
**Expected:** canonical `backend.models.schemas.ScanResult`  
**Actual:** HTTP responses lack required canonical provenance and safe input
reference fields, and permit nullable risk/confidence and incompatible severity
values.  
**Impact:** neither the frontend nor n8n can safely start an investigation from
an HTTP scan result.  
**Recommended fix:** make Module 1 produce the canonical contract at the server
boundary, preserving source-derived provenance and input references.

## Module 3C production blocker

The checked-in n8n workflow is a text/URL mock-capable workflow. It does not
implement the required menu/state machine, media uploads, `INVESTIGATE` action,
or callback ownership checks by `telegram_user_id + chat_id`. It must not be
called production-ready or activated for shared users until those requirements
are implemented using durable per-conversation state.
