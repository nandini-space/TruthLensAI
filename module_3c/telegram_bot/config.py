"""Environment-only configuration for the Telegram adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass


class BotConfigurationError(RuntimeError):
    """Raised when the Telegram adapter cannot be configured safely."""


@dataclass(frozen=True, slots=True)
class TelegramBotSettings:
    """Only non-empty environment values are accepted; tokens are never logged."""

    token: str

    @classmethod
    def from_environment(cls) -> "TelegramBotSettings":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise BotConfigurationError(
                "TELEGRAM_BOT_TOKEN is required to start the TruthLensAI Telegram bot."
            )
        return cls(token=token)
