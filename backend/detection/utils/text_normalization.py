"""Safe text normalization for deterministic analysis without mutating input."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\ufeff]")
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class NormalizedText:
    original: str
    normalized: str
    analysis: str


def normalize_text(content: str) -> NormalizedText:
    """Normalize Unicode and whitespace; use case-folding only for matching."""
    normalized = unicodedata.normalize("NFKC", content)
    normalized = _ZERO_WIDTH.sub("", normalized)
    normalized = _WHITESPACE.sub(" ", normalized).strip()
    return NormalizedText(
        original=content,
        normalized=normalized,
        analysis=normalized.casefold(),
    )
