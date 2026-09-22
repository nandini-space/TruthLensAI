# Privacy notice

TruthLensAI processes text, URLs, and uploaded media submitted for threat analysis. Module 1 returns detection signals, extracted entities, an explanation, and a recommendation. These are assessments, not certainty.

The local API does not persist ordinary Module 1 scan inputs or results. Temporary uploaded files are removed after each request. If Module 2 Supabase persistence is configured, completed investigation snapshots include the canonical scan result, evidence, intelligence results, incident data, reports, and dry-run response records. Retention is controlled by the deployment owner; configure a documented retention policy before handling personal or sensitive data.

Optional third parties are used only when configured: VirusTotal for threat intelligence and Telegram/n8n for the Telegram interface. Do not submit data to these services unless you are authorized to do so. The Python Telegram bot is a prototype; n8n is the intended production update owner.

Operational logs should contain request IDs, timestamps, modality, and status, but never raw submitted content, credentials, bot tokens, or authorization headers. Contact the deployment owner for deletion, retention, or data-access requests.
