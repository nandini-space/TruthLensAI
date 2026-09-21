"""Conservative, provider-independent IOC extraction from ``ScanResult`` entities."""

from __future__ import annotations

import ipaddress
import re
from typing import Callable
from urllib.parse import urlsplit, urlunsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from backend.intelligence.models import Indicator, IndicatorType
from backend.models.schemas import ExtractedEntity, ScanResult


_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_HASH_LENGTHS = {32, 40, 64, 128}
_HEX_PATTERN = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_PHONE_PATTERN = re.compile(r"^\+?[0-9][0-9 ()-]*[0-9]$")
_NON_INDICATOR_ENTITY_TYPES = {
    "date",
    "location",
    "name",
    "number",
    "organization",
    "person",
    "prose",
    "text",
    "time",
}


def _strip_surrounding_punctuation(value: str) -> str:
    """Remove unambiguous prose punctuation without changing meaningful content."""

    candidate = value.strip().lstrip("([{'\"")
    candidate = candidate.rstrip(".,;!?'\"")
    if candidate.endswith(")") and candidate.count(")") > candidate.count("("):
        candidate = candidate[:-1]
    if candidate.endswith("]") and candidate.count("]") > candidate.count("["):
        candidate = candidate[:-1]
    return candidate


def _normalize_url(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value)
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not hostname or any(character.isspace() for character in candidate):
        return None
    normalized_host = hostname.rstrip(".").lower()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"

    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = f"{parsed.netloc.rsplit('@', 1)[0]}@"
    normalized_netloc = f"{userinfo}{normalized_host}"
    if port is not None:
        normalized_netloc = f"{normalized_netloc}:{port}"

    return urlunsplit(
        (parsed.scheme.lower(), normalized_netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _normalize_email(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value)
    return candidate.lower() if _EMAIL_PATTERN.fullmatch(candidate) else None


def _normalize_ipv4(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value)
    try:
        parsed = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError:
        return None
    return str(parsed)


def _normalize_hash(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value)
    if len(candidate) in _HASH_LENGTHS and _HEX_PATTERN.fullmatch(candidate):
        return candidate.lower()
    return None


def _normalize_phone(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value)
    if not _PHONE_PATTERN.fullmatch(candidate):
        return None
    digits = "".join(character for character in candidate if character.isdigit())
    has_formatting = candidate.startswith("+") or any(
        character in " ()-" for character in candidate
    )
    if not has_formatting or not 10 <= len(digits) <= 15:
        return None
    return f"+{digits}" if candidate.startswith("+") else digits


def _normalize_domain(value: str) -> str | None:
    candidate = _strip_surrounding_punctuation(value).lower().rstrip(".")
    if "@" in candidate or not _DOMAIN_PATTERN.fullmatch(candidate):
        return None
    return candidate


_NORMALIZERS: tuple[tuple[IndicatorType, Callable[[str], str | None]], ...] = (
    (IndicatorType.URL, _normalize_url),
    (IndicatorType.EMAIL, _normalize_email),
    (IndicatorType.IP, _normalize_ipv4),
    (IndicatorType.HASH, _normalize_hash),
    (IndicatorType.PHONE, _normalize_phone),
    (IndicatorType.DOMAIN, _normalize_domain),
)


def _classify_entity(entity: ExtractedEntity) -> tuple[IndicatorType, str] | None:
    """Return the most specific valid indicator classification for one entity."""

    if entity.entity_type.strip().lower() in _NON_INDICATOR_ENTITY_TYPES:
        return None

    for indicator_type, normalizer in _NORMALIZERS:
        normalized_value = normalizer(entity.value)
        if normalized_value is not None:
            return indicator_type, normalized_value
    return None


def _indicator_id(indicator_type: IndicatorType, value: str) -> UUID:
    """Create a stable ID from the normalized observable, independent of a scan."""

    return uuid5(NAMESPACE_URL, f"truthlensai:indicator:{indicator_type.value}:{value}")


def extract_indicators(scan_result: ScanResult) -> list[Indicator]:
    """Extract, normalize, and deterministically deduplicate scan observables.

    Only ``ScanResult.extracted_entities`` is examined. This function never
    assigns reputation and does not make network, database, or provider calls.
    """

    indicators: list[Indicator] = []
    seen: set[tuple[IndicatorType, str]] = set()

    for entity in scan_result.extracted_entities:
        classification = _classify_entity(entity)
        if classification is None:
            continue
        indicator_type, normalized_value = classification
        key = (indicator_type, normalized_value)
        if key in seen:
            continue
        seen.add(key)

        context = {
            "entity_type": entity.entity_type,
            "entity_metadata": entity.metadata,
        }
        if entity.normalized_value is not None:
            context["entity_normalized_value"] = entity.normalized_value
        indicators.append(
            Indicator(
                indicator_id=_indicator_id(indicator_type, normalized_value),
                type=indicator_type,
                value=normalized_value,
                source="scan_result",
                confidence=entity.confidence,
                context=context,
            )
        )

    return indicators
