# Security policy

## Supported deployment posture

TruthLensAI is not production-ready by default. Deploy the FastAPI service and database on private networks, terminate TLS at the edge, and keep credentials out of the repository. The supplied Supabase repository uses a service-role key only on the backend.

The API accepts an optional `TRUTHLENSAI_API_KEY`. When configured, every API route except `/health` requires it in `X-TruthLens-API-Key`; configure n8n with that secret as a credential. The optional in-process per-IP/per-route rate limit is controlled by `TRUTHLENSAI_RATE_LIMIT_PER_MINUTE`. It is not a replacement for gateway-level rate limiting.

Module 1 rejects literal private, loopback, link-local, multicast, reserved, and localhost URL targets. It currently performs local URL analysis and does not fetch submitted URLs. Any future network-fetching analyzer must resolve and validate every redirect target, restrict response size and timeouts, and defend against DNS rebinding.

Uploads are size-limited, extension/MIME-checked, staged in temporary storage, and removed after processing. Detection libraries remain responsible for format-level parsing; deploy media processing in an isolated worker where untrusted media is accepted.

## Secrets

Never commit `.env`, tokens, API keys, passwords, authorization headers, or n8n credential exports. `.env.example` contains placeholders only. Review n8n exports before sharing them.

## Reporting a vulnerability

Do not file public issues containing exploit details or secrets. Report the affected component, reproduction steps, impact, and a contact method privately to the project maintainer. Rotate any disclosed credential immediately.
