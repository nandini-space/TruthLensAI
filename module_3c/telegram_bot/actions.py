"""Stable, short callback actions for the initial Telegram interface."""

from enum import StrEnum


class CallbackAction(StrEnum):
    """Actions currently supported by the Telegram-only prototype."""

    NEW_SCAN = "NEW_SCAN"
    SCAN_HISTORY = "SCAN_HISTORY"
    HELP = "HELP"
    SCAN_TEXT = "SCAN_TEXT"
    SCAN_URL = "SCAN_URL"
    SCAN_IMAGE = "SCAN_IMAGE"
    SCAN_AUDIO = "SCAN_AUDIO"
    SCAN_VIDEO = "SCAN_VIDEO"
    CANCEL = "CANCEL"


SCAN_ACTIONS = frozenset(
    {
        CallbackAction.SCAN_TEXT,
        CallbackAction.SCAN_URL,
        CallbackAction.SCAN_IMAGE,
        CallbackAction.SCAN_AUDIO,
        CallbackAction.SCAN_VIDEO,
    }
)
