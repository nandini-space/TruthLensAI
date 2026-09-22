"""Pure presentation logic for the Telegram prototype; no network or backend calls."""

from __future__ import annotations

from dataclasses import dataclass

from .actions import CallbackAction, SCAN_ACTIONS


@dataclass(frozen=True, slots=True)
class ButtonSpec:
    """Telegram-independent representation of one inline button."""

    label: str
    action: CallbackAction


@dataclass(frozen=True, slots=True)
class ReplySpec:
    """Telegram-independent reply that handlers render through the Telegram SDK."""

    text: str
    keyboard: tuple[tuple[ButtonSpec, ...], ...]


def main_menu(*, welcome: bool = False) -> ReplySpec:
    """Return the top-level menu without keeping conversation state."""

    prefix = (
        "Welcome to TruthLensAI.\n\n"
        "I can help you analyze suspicious content. Scanning and intelligence "
        "connections will be added in later tasks.\n\n"
        if welcome
        else ""
    )
    return ReplySpec(
        text=prefix + "Choose an option:",
        keyboard=(
            (ButtonSpec("🔍 New Scan", CallbackAction.NEW_SCAN),),
            (ButtonSpec("📋 Scan History", CallbackAction.SCAN_HISTORY),),
            (ButtonSpec("ℹ️ Help", CallbackAction.HELP),),
        ),
    )


def help_reply() -> ReplySpec:
    return ReplySpec(
        text=(
            "TruthLensAI will help assess suspicious text, URLs, images, audio, "
            "and video.\n\n"
            "This prototype only lets you choose an input type; it does not scan "
            "content or contact the backend, n8n, Module 1, or Module 2 yet."
        ),
        keyboard=((ButtonSpec("⬅️ Main Menu", CallbackAction.CANCEL),),),
    )


def scan_menu() -> ReplySpec:
    return ReplySpec(
        text="Choose what you want to analyze:",
        keyboard=(
            (
                ButtonSpec("📝 Text", CallbackAction.SCAN_TEXT),
                ButtonSpec("🔗 URL", CallbackAction.SCAN_URL),
            ),
            (
                ButtonSpec("🖼 Image", CallbackAction.SCAN_IMAGE),
                ButtonSpec("🎵 Audio", CallbackAction.SCAN_AUDIO),
            ),
            (ButtonSpec("🎥 Video", CallbackAction.SCAN_VIDEO),),
            (ButtonSpec("❌ Cancel", CallbackAction.CANCEL),),
        ),
    )


def selected_input(action: CallbackAction) -> ReplySpec:
    """Confirm only the selected input type; scanning is intentionally absent."""

    labels = {
        CallbackAction.SCAN_TEXT: "Text",
        CallbackAction.SCAN_URL: "URL",
        CallbackAction.SCAN_IMAGE: "Image",
        CallbackAction.SCAN_AUDIO: "Audio",
        CallbackAction.SCAN_VIDEO: "Video",
    }
    return ReplySpec(
        text=(
            f"{labels[action]} scan selected.\n\n"
            "Backend integration will be connected in a later task. "
            "Please cancel or return to the main menu."
        ),
        keyboard=((ButtonSpec("❌ Cancel", CallbackAction.CANCEL),),),
    )


def scan_history_unavailable() -> ReplySpec:
    return ReplySpec(
        text="Scan History is not available yet.",
        keyboard=((ButtonSpec("⬅️ Main Menu", CallbackAction.CANCEL),),),
    )


def unexpected_input() -> ReplySpec:
    return ReplySpec(
        text="Please use /start or choose an option from the menu.",
        keyboard=main_menu().keyboard,
    )


def unknown_action() -> ReplySpec:
    return ReplySpec(
        text="That option is unavailable. Returning to the main menu.",
        keyboard=main_menu().keyboard,
    )


def reply_for_action(callback_data: str | None) -> ReplySpec:
    """Resolve known callbacks safely without interpreting user-provided text."""

    try:
        action = CallbackAction(callback_data or "")
    except ValueError:
        return unknown_action()
    if action is CallbackAction.NEW_SCAN:
        return scan_menu()
    if action is CallbackAction.SCAN_HISTORY:
        return scan_history_unavailable()
    if action is CallbackAction.HELP:
        return help_reply()
    if action is CallbackAction.CANCEL:
        return main_menu()
    if action in SCAN_ACTIONS:
        return selected_input(action)
    return unknown_action()
