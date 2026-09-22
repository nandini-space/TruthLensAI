# Module 3C mock Telegram workflow

`truthlens_module_3c_mock.json` is the Task 3C-3 proof-of-flow workflow:

```text
Telegram -> n8n -> mock normalized TruthLensAI result -> Telegram
```

It has no HTTP Request node and makes no Module 1, Module 2, n8n-to-backend,
or external intelligence call. The mock response follows the normalized
envelope in `MODULE_3C_INTEGRATION.md`; the explanatory text explicitly marks
it as mock/test data.

## Import and activation

1. In n8n, import `truthlens_module_3c_mock.json`.
2. Create or select a Telegram credential in n8n for both Telegram nodes.
   Store the bot token only in n8n credentials; the workflow JSON contains no
   token or credential ID.
3. Save and activate the workflow.
4. Send a text message or URL to the bot. The workflow sends a formatted
   `TruthLensAI Test Scan (MOCK)` response.

Telegram supports one active update consumer per bot token. This workflow's
Telegram Trigger must therefore be tested with the Python polling bot stopped,
or with a separate test bot token. The existing Python bot remains useful for
its Task 3C-2 menu tests, but it must not run polling concurrently with this
n8n trigger.

## Behavior and test cases

| Case | Input | Expected result |
|---|---|---|
| TC-01 | `/start` while Python bot is the active consumer | Existing `/start` menu works. |
| TC-02 | Normal text while workflow is active | Mock text result returns to the originating chat. |
| TC-03 | HTTP(S) URL | Detected as `url`; mock result returns. |
| TC-04 | Empty/unsupported update | Safe validation message; no stack trace. |
| TC-05 | Image | Recognized as `image`; mock result only, no download or scanning. |
| TC-06 | Audio | Recognized as `audio`; mock result only, no download or scanning. |
| TC-07 | Video | Recognized as `video`; mock result only, no download or scanning. |
| TC-08 | Inspect workflow nodes | No Module 1 endpoint/API call exists. |
| TC-09 | Inspect workflow nodes | No Module 2 endpoint/API call exists. |
| TC-10 | Inspect export | No bot token or credentials are stored in JSON. |
| TC-11 | `python -m unittest tests.test_telegram_bot` | Existing bot tests pass. |
| TC-12 | Deactivate/activate workflow | It can be reactivated after credentials are configured, with no source change. |

Telegram Send Message failures are recorded by n8n as failed executions; a
message cannot be delivered when Telegram itself rejects the send. Configure
n8n's normal execution/error notifications for operators, and never send raw
execution errors or credentials back to users.
