"""Executable polling entry point for the initial, isolated Telegram bot."""

from __future__ import annotations

import logging

from telegram.error import TelegramError
from telegram.ext import Application, ApplicationBuilder, CallbackQueryHandler, CommandHandler, MessageHandler, filters

from .config import BotConfigurationError, TelegramBotSettings
from .handlers import callback_action, cancel, help_command, on_error, start, unexpected_message


LOGGER = logging.getLogger(__name__)


class BotStartupError(RuntimeError):
    """Raised after a startup/API failure without exposing operational details."""


def create_application(settings: TelegramBotSettings) -> Application:
    """Build the Telegram-only app without contacting Telegram or the backend."""

    application = ApplicationBuilder().token(settings.token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CallbackQueryHandler(callback_action))
    application.add_handler(MessageHandler(filters.ALL, unexpected_message))
    application.add_error_handler(on_error)
    return application


def run_bot() -> None:
    """Start polling only after configuration succeeds; no backend clients exist here."""

    settings = TelegramBotSettings.from_environment()
    application = create_application(settings)
    try:
        application.run_polling()
    except TelegramError as error:
        LOGGER.error("Telegram API connection failed: %s", type(error).__name__)
        raise BotStartupError("Unable to connect to the Telegram API.") from None
    except Exception as error:
        LOGGER.error("Telegram bot startup failed: %s", type(error).__name__)
        raise BotStartupError("Unable to start the TruthLensAI Telegram bot.") from None


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        run_bot()
    except (BotConfigurationError, BotStartupError) as error:
        LOGGER.error("%s", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
