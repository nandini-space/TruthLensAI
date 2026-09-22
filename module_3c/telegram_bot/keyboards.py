"""Telegram SDK rendering for the adapter's pure button specifications."""

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from .interaction import ReplySpec


def to_inline_keyboard(reply: ReplySpec) -> InlineKeyboardMarkup:
    """Render callback actions only; no user content is placed in callback data."""

    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(button.label, callback_data=button.action.value)
                for button in row
            ]
            for row in reply.keyboard
        ]
    )
