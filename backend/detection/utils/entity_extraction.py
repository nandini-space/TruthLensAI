"""Local extraction of textual indicators; no intelligence lookups occur here."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..schemas import ExtractedEntities


_URL = re.compile(r"(?i)(?<!@)\b(?:https?://|www\.)[^\s<>\"']+")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
_DOMAIN = re.compile(
    r"(?i)(?<![@/])\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|io|co|ai|app|dev|info|biz|in|uk|us|me)\b"
)
_PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{3,4}(?!\w)")
_TRAILING_PUNCTUATION = ".,;:!?)]}\"'"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    return [value for value in values if not (value.casefold() in seen or seen.add(value.casefold()))]


def _clean_url(value: str) -> str:
    return value.rstrip(_TRAILING_PUNCTUATION)


def _url_domain(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname.casefold() if parsed.hostname else None


def _valid_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15 and ("+" in value or len(digits) >= 10 or bool(re.search(r"[(). -]", value)))


def extract_entities(content: str) -> ExtractedEntities:
    """Extract conservative URLs, domains, emails, and phone numbers from text."""
    urls = _unique([_clean_url(match.group(0)) for match in _URL.finditer(content)])
    url_domains = [domain for url in urls if (domain := _url_domain(url))]
    email_addresses = _unique([match.group(0) for match in _EMAIL.finditer(content)])
    standalone_domains = [match.group(0).casefold() for match in _DOMAIN.finditer(content)]
    domains = _unique(url_domains + standalone_domains)
    phone_numbers = _unique(
        [match.group(0).strip() for match in _PHONE.finditer(content) if _valid_phone(match.group(0))]
    )
    return ExtractedEntities(
        urls=urls,
        domains=domains,
        email_addresses=email_addresses,
        phone_numbers=phone_numbers,
    )
