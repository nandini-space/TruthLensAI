"""Async Telegram handlers with no Module 1, Module 2, n8n, or backend calls."""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from .interaction import help_reply, main_menu, reply_for_action, unexpected_input
from .keyboards import to_inline_keyboard


LOGGER = logging.getLogger(__name__)


async def _send_message(update: Update, reply) -> None:
    if update.effective_message is not None:
        await update.effective_message.reply_text(
            reply.text, reply_markup=to_inline_keyboard(reply)
        )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the welcome message and prototype main menu."""

    await _send_message(update, main_menu(welcome=True))


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Explain the prototype without promising unavailable integrations."""

    await _send_message(update, help_reply())


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """There is no persisted state yet; returning to the menu is cancellation."""

    await _send_message(update, main_menu())


async def callback_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Resolve a compact known callback and render the next prototype screen."""

    query = update.callback_query
    if query is None:
        return
    await query.answer()
    reply = reply_for_action(query.data)
    await query.edit_message_text(reply.text, reply_markup=to_inline_keyboard(reply))


async def unexpected_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Do not log message contents, which may be sensitive user material."""

    LOGGER.info("Received unsupported Telegram message type.")
    await _send_message(update, unexpected_input())


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log only the error type to avoid exposing token or user-content details."""

    error_type = type(context.error).__name__ if context.error is not None else "UnknownError"
    LOGGER.error("Telegram handler failed: %s", error_type)
