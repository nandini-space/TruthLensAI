"""Thin VirusTotal v3 adapter that returns provider-neutral intelligence contracts."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from backend.config import Settings
from backend.intelligence.models import (
    Indicator,
    IndicatorType,
    ProviderStatus,
    Reputation,
    ThreatIntelFinding,
    ThreatIntelResult,
)


_BASE_URL = "https://www.virustotal.com/api/v3"
_SOURCE = "virustotal"


class VirusTotalProvider:
    """Look up supported indicators in VirusTotal without exposing its schema.

    ``client`` exists for lifecycle control and offline testing. When omitted, a
    short-lived ``httpx.Client`` is created only for configured lookups.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        settings_key = Settings.from_environment().virustotal_api_key
        self._api_key = api_key or settings_key
        self._timeout = timeout
        self._client = client

    def lookup(self, indicator: Indicator) -> ThreatIntelResult:
        """Look up an indicator and safely map the response to ``ThreatIntelResult``."""

        queried_at = datetime.now(timezone.utc)
        if not self._api_key:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.UNAVAILABLE,
                "api_key_not_configured",
                "VirusTotal API key is not configured.",
            )

        endpoint = self._endpoint_for(indicator)
        if endpoint is None:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.UNAVAILABLE,
                "unsupported_indicator_type",
                f"VirusTotal lookup is not available for {indicator.type.value} indicators.",
            )

        try:
            response = self._get(endpoint)
        except httpx.TimeoutException:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.UNAVAILABLE,
                "request_timeout",
                "VirusTotal request timed out.",
            )
        except httpx.RequestError:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.UNAVAILABLE,
                "connection_error",
                "VirusTotal could not be reached.",
            )

        if response.status_code == 200:
            return self._parse_success(indicator, queried_at, response)
        if response.status_code == 404:
            return self._result(
                indicator,
                queried_at,
                Reputation.UNKNOWN,
                ProviderStatus.SUCCESS,
                "not_found",
                "VirusTotal has no existing record for this indicator.",
            )
        if response.status_code in {401, 403}:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.ERROR,
                "authentication_error",
                "VirusTotal authentication or authorization failed.",
            )
        if response.status_code == 429:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.UNAVAILABLE,
                "rate_limited",
                "VirusTotal rate limit was reached.",
            )
        if response.status_code >= 500:
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.ERROR,
                "provider_server_error",
                "VirusTotal returned a server error.",
            )
        return self._non_success_result(
            indicator,
            queried_at,
            ProviderStatus.ERROR,
            "provider_request_error",
            "VirusTotal rejected the lookup request.",
        )

    def _get(self, endpoint: str) -> httpx.Response:
        headers = {"x-apikey": self._api_key or "", "accept": "application/json"}
        url = f"{_BASE_URL}{endpoint}"
        if self._client is not None:
            return self._client.get(url, headers=headers, timeout=self._timeout)
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(url, headers=headers)

    @staticmethod
    def _endpoint_for(indicator: Indicator) -> str | None:
        if indicator.type is IndicatorType.HASH:
            return f"/files/{quote(indicator.value, safe='')}"
        if indicator.type is IndicatorType.DOMAIN:
            return f"/domains/{quote(indicator.value, safe='')}"
        if indicator.type is IndicatorType.IP:
            return f"/ip_addresses/{quote(indicator.value, safe='')}"
        if indicator.type is IndicatorType.URL:
            identifier = base64.urlsafe_b64encode(indicator.value.encode("utf-8"))
            return f"/urls/{identifier.decode('ascii').rstrip('=')}"
        return None

    def _parse_success(
        self, indicator: Indicator, queried_at: datetime, response: httpx.Response
    ) -> ThreatIntelResult:
        try:
            payload = response.json()
        except (TypeError, ValueError):
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.ERROR,
                "malformed_response",
                "VirusTotal returned an invalid response.",
            )
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            return self._non_success_result(
                indicator,
                queried_at,
                ProviderStatus.ERROR,
                "unexpected_response",
                "VirusTotal returned an unexpected response structure.",
            )

        data = payload["data"]
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            return self._partial_result(indicator, queried_at, "missing_attributes")
        statistics = self._statistics(attributes.get("last_analysis_stats"))
        if statistics is None:
            return self._partial_result(indicator, queried_at, "missing_analysis_statistics")

        reputation = self._reputation_from(statistics)
        timestamp = self._provider_timestamp(attributes.get("last_analysis_date"))
        reference = self._provider_reference(data)
        finding = ThreatIntelFinding(
            source=_SOURCE,
            category="analysis_statistics",
            description=self._statistics_description(statistics),
            timestamp=timestamp,
            metadata={"analysis_statistics": statistics},
        )
        return ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source=_SOURCE,
            queried_at=queried_at,
            status=ProviderStatus.SUCCESS,
            findings=[finding],
            provider_reference=reference,
            metadata={"analysis_statistics": statistics},
        )

    @staticmethod
    def _statistics(value: Any) -> dict[str, int] | None:
        if not isinstance(value, dict):
            return None
        keys = ("malicious", "suspicious", "harmless", "undetected")
        statistics: dict[str, int] = {}
        for key in keys:
            count = value.get(key, 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                return None
            statistics[key] = count
        return statistics

    @staticmethod
    def _reputation_from(statistics: dict[str, int]) -> Reputation:
        if statistics["malicious"] > 0:
            return Reputation.MALICIOUS
        if statistics["suspicious"] > 0:
            return Reputation.SUSPICIOUS
        if statistics["harmless"] > 0:
            return Reputation.BENIGN
        return Reputation.UNKNOWN

    @staticmethod
    def _statistics_description(statistics: dict[str, int]) -> str:
        return (
            "VirusTotal analysis statistics: "
            f"{statistics['malicious']} malicious, "
            f"{statistics['suspicious']} suspicious, "
            f"{statistics['harmless']} harmless, "
            f"{statistics['undetected']} undetected."
        )

    @staticmethod
    def _provider_timestamp(value: Any) -> datetime | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def _provider_reference(data: dict[str, Any]) -> str | None:
        links = data.get("links")
        if isinstance(links, dict) and isinstance(links.get("self"), str):
            return links["self"]
        return None

    def _partial_result(
        self, indicator: Indicator, queried_at: datetime, reason: str
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=Reputation.UNKNOWN,
            source=_SOURCE,
            queried_at=queried_at,
            status=ProviderStatus.PARTIAL,
            findings=[
                ThreatIntelFinding(
                    source=_SOURCE,
                    category="incomplete_response",
                    description="VirusTotal response did not include usable analysis statistics.",
                )
            ],
            metadata={"reason": reason},
        )

    def _non_success_result(
        self,
        indicator: Indicator,
        queried_at: datetime,
        status: ProviderStatus,
        reason: str,
        description: str,
    ) -> ThreatIntelResult:
        return self._result(
            indicator,
            queried_at,
            Reputation.UNAVAILABLE,
            status,
            reason,
            description,
        )

    @staticmethod
    def _result(
        indicator: Indicator,
        queried_at: datetime,
        reputation: Reputation,
        status: ProviderStatus,
        category: str,
        description: str,
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            reputation=reputation,
            source=_SOURCE,
            queried_at=queried_at,
            status=status,
            findings=[
                ThreatIntelFinding(
                    source=_SOURCE,
                    category=category,
                    description=description,
                )
            ],
            metadata={"reason": category},
        )
