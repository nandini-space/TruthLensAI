# TruthLensAI Telegram Bot prototype/reference (Module 3C-2)

This is an isolated local prototype/reference implementation. Production
Telegram UI and update consumption belong to the n8n workflow. Its polling implementation
provides a welcome/menu flow and input-type selection prototype; it does not
scan content or contact Module 1, Module 2, or any TruthLensAI backend API.

## Setup

1. Create a bot with Telegram's BotFather and copy its token.
2. Set `TELEGRAM_BOT_TOKEN` in the process environment or use deployment
   tooling that loads a local `.env` file. This package deliberately does not
   load `.env` files itself.
3. Use the placeholder in the root `.env.example` as a configuration reference;
   never commit a real token.
4. Create and activate a Python virtual environment, then install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Run

Run from the repository root after setting `TELEGRAM_BOT_TOKEN`:

```bash
# PowerShell
$env:TELEGRAM_BOT_TOKEN = "your-token"
python -m module_3c.telegram_bot.bot
```

The bot uses long polling. A missing token stops startup with a clear
configuration error. Telegram connection/startup failures are logged without
logging the token or user message contents.

## Test

The unit tests do not need a token or network access:

```bash
python -m unittest tests.test_telegram_bot
```

## Current behavior

- `/start` shows a welcome message and New Scan, Scan History, and Help menu.
- `/help` explains the planned capabilities.
- `/cancel` returns to the main menu.
- New Scan displays Text, URL, Image, Audio, Video, and Cancel choices.
- Choosing a type only confirms the selection.

Scan history, Telegram media handling, backend calls, Module 1 scans, Module 2
investigations, feedback actions, and real response actions are intentionally
not implemented in this bot process.

## Task 3C-4 n8n Module 1 workflow

The importable mock workflow is at
[`n8n/workflows/truthlens_module_3c_mock.json`](../../n8n/workflows/truthlens_module_3c_mock.json).
It supports Telegram -> n8n -> Module 1 -> normalized response -> Telegram for
text and URLs when real mode is enabled, while retaining a configurable offline
mock mode. Image, audio, and video are recognized but not sent to Module 1 in
this task. See its
[workflow instructions](../../n8n/workflows/README.md) for n8n credentials,
import, activation, and test cases.

Never run this Python polling bot and the production n8n Telegram Trigger with
the same bot token: Telegram permits only one active update consumer. Use a
separate test bot for this prototype, or stop it before activating n8n.
