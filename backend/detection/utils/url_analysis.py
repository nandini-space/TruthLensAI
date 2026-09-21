"""Local URL parsing and explainable heuristic extraction; never performs I/O."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

from ..config import UrlRiskConfig
from ..schemas import Signal


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    is_ip_address: bool
    registered_looking_domain: str | None


def parse_url(content: str) -> ParsedUrl | None:
    """Parse a URL safely, adding HTTPS only when no scheme was supplied."""
    original = content.strip()
    if not original or any(character.isspace() for character in original):
        return None
    candidate = original if "://" in original else f"https://{original.lstrip('/') }"
    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname.rstrip(".").casefold()
    if not re.fullmatch(r"[a-z0-9._:-]+", hostname):
        return None
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
    labels = hostname.split(".")
    registered_looking_domain = None if is_ip_address or len(labels) < 2 else ".".join(labels[-2:])
    normalized = urlunparse((parsed.scheme.casefold(), parsed.netloc, unquote(parsed.path), parsed.params, parsed.query, parsed.fragment))
    return ParsedUrl(
        original=original,
        normalized=normalized,
        scheme=parsed.scheme.casefold(),
        hostname=hostname,
        port=port,
        path=unquote(parsed.path),
        query=parsed.query,
        fragment=parsed.fragment,
        username=parsed.username,
        is_ip_address=is_ip_address,
        registered_looking_domain=registered_looking_domain,
    )


def _signal(code: str, description: str, evidence: str, strength: int) -> Signal:
    return Signal(code=code, description=description, source="url_rule", details={"evidence": evidence, "strength": strength})


def detect_url_signals(parsed: ParsedUrl, config: UrlRiskConfig) -> list[Signal]:
    """Identify conservative, evidence-backed local URL characteristics."""
    signals: list[Signal] = []
    if parsed.is_ip_address:
        signals.append(_signal("ip_address_hostname", "The hostname is an IP address.", parsed.hostname, 20))
    if parsed.hostname in config.shortener_domains:
        signals.append(_signal("url_shortener", "The hostname is a URL-shortening service.", parsed.hostname, 10))
    if parsed.scheme == "http":
        signals.append(_signal("insecure_scheme", "The URL uses HTTP rather than HTTPS.", parsed.scheme, 5))
    if parsed.username is not None:
        signals.append(_signal("explicit_url_credentials", "The URL contains explicit user credentials.", parsed.username, 40))
    if not parsed.is_ip_address and len(parsed.hostname.split(".")) > config.max_hostname_labels:
        signals.append(_signal("excessive_subdomains", "The hostname contains unusually many labels.", parsed.hostname, 12))
    if parsed.port is not None and parsed.port not in config.common_ports:
        signals.append(_signal("uncommon_port", "The URL specifies an uncommon port.", str(parsed.port), 14))

    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", parsed.original)
    encoded_delimiter = re.search(r"%(?:2f|3a|3f|40|5c)", parsed.original, re.IGNORECASE)
    if len(encoded_parts) >= config.encoded_sequence_threshold or encoded_delimiter:
        signals.append(_signal("encoded_url_structure", "The URL contains potentially obfuscating percent-encoding.", encoded_delimiter.group(0) if encoded_delimiter else encoded_parts[0], 12))

    path_terms = {segment.casefold() for segment in parsed.path.split("/") if segment}
    matched_path_terms = sorted(path_terms & config.credential_path_terms)
    if matched_path_terms:
        signals.append(_signal("credential_related_path", "The path contains account or credential-related terms.", matched_path_terms[0], 10))

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for key, value in query_pairs:
        normalized_key = key.casefold()
        decoded_value = unquote(value)
        if normalized_key in config.redirect_parameter_names and re.search(r"(?:https?://|www\.)", decoded_value, re.IGNORECASE):
            signals.append(_signal("redirect_destination_parameter", "A query parameter contains a destination URL.", key, 12))
            break
        if normalized_key in config.credential_parameter_names:
            signals.append(_signal("credential_query_parameter", "A query parameter is named for a credential or code.", key, 15))
            break

    if _has_brand_like_pattern(parsed, config):
        signals.append(_signal("brand_like_hostname", "The hostname contains a brand-like token in an unrelated domain.", parsed.hostname, 18))
    return signals


def _has_brand_like_pattern(parsed: ParsedUrl, config: UrlRiskConfig) -> bool:
    if parsed.is_ip_address or not parsed.registered_looking_domain:
        return False
    host = parsed.hostname
    for brand in config.demonstration_brand_terms:
        if brand in host and parsed.registered_looking_domain not in {f"{brand}.com", f"{brand}.org"}:
            return True
    return False
