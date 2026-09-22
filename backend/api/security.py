"""Small HTTP-boundary safeguards that do not alter detection internals."""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from threading import Lock
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status


_LOCK = Lock()
_REQUESTS: dict[str, deque[float]] = defaultdict(deque)


def reject_unsafe_url(value: str) -> str:
    """Reject literal/private targets before a URL reaches any future fetcher.

    Module 1 currently performs local lexical URL analysis and does not download
    URLs. Keeping this guard at the HTTP boundary prevents an unsafe target from
    becoming reachable if a network-backed analyzer is added later.
    """

    parsed = urlparse(value)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise ValueError("A hostname is required.")
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        raise ValueError("Local and private URL targets are not allowed.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return value
    if not address.is_global:
        raise ValueError("Local and private URL targets are not allowed.")
    return value


def enforce_rate_limit(request: Request) -> None:
    """Bound unauthenticated API use by client IP when configured."""

    limit = getattr(request.app.state, "rate_limit_per_minute", 0)
    if not limit:
        return
    client = request.client.host if request.client else "unknown"
    key = f"{client}:{request.url.path}"
    now = time.monotonic()
    with _LOCK:
        bucket = _REQUESTS[key]
        while bucket and bucket[0] <= now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        bucket.append(now)
