"""Offline tests for the VirusTotal provider adapter."""

from __future__ import annotations

import base64
import os
import unittest
from uuid import UUID

import httpx

from backend.intelligence.models import Indicator, IndicatorType, ProviderStatus, Reputation
from backend.intelligence.virustotal import VirusTotalProvider


class VirusTotalProviderTests(unittest.TestCase):
    api_key = "test-key-not-a-secret"

    def indicator(self, indicator_type: IndicatorType, value: str) -> Indicator:
        return Indicator(
            indicator_id=UUID("a5816e23-1735-4d55-a7dc-d6749105e660"),
            type=indicator_type,
            value=value,
            source="test",
        )

    def provider_for(self, handler: httpx.MockTransport.Handler) -> VirusTotalProvider:
        client = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(client.close)
        return VirusTotalProvider(api_key=self.api_key, client=client)

    @staticmethod
    def success_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 0,
                            "harmless": 4,
                            "undetected": 60,
                        },
                        "last_analysis_date": 1_790_000_000,
                    },
                    "links": {"self": str(request.url)},
                }
            },
        )

    def test_missing_key_and_instantiation_are_safe(self) -> None:
        old_value = os.environ.pop("VIRUSTOTAL_API_KEY", None)
        try:
            provider = VirusTotalProvider()
            result = provider.lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        finally:
            if old_value is not None:
                os.environ["VIRUSTOTAL_API_KEY"] = old_value
        self.assertEqual(result.status, ProviderStatus.UNAVAILABLE)
        self.assertEqual(result.reputation, Reputation.UNAVAILABLE)

    def test_supported_endpoints_and_url_identifier(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            self.assertEqual(request.headers["x-apikey"], self.api_key)
            return self.success_response(request)

        provider = self.provider_for(handler)
        provider.lookup(self.indicator(IndicatorType.HASH, "a" * 64))
        provider.lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        provider.lookup(self.indicator(IndicatorType.IP, "8.8.8.8"))
        provider.lookup(self.indicator(IndicatorType.URL, "https://example.com/login"))
        expected_url_id = base64.urlsafe_b64encode(
            b"https://example.com/login"
        ).decode("ascii").rstrip("=")
        self.assertEqual(
            [request.url.path for request in requests],
            [
                f"/api/v3/files/{'a' * 64}",
                "/api/v3/domains/example.com",
                "/api/v3/ip_addresses/8.8.8.8",
                f"/api/v3/urls/{expected_url_id}",
            ],
        )

    def test_unsupported_types_do_not_attempt_requests(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        provider = self.provider_for(handler)
        for indicator_type, value in (
            (IndicatorType.EMAIL, "user@example.com"),
            (IndicatorType.PHONE, "+919876543210"),
        ):
            with self.subTest(indicator_type=indicator_type):
                result = provider.lookup(self.indicator(indicator_type, value))
                self.assertEqual(result.status, ProviderStatus.UNAVAILABLE)
                self.assertEqual(result.reputation, Reputation.UNAVAILABLE)

    def test_http_statuses_are_safe_and_non_benign(self) -> None:
        expected = {
            400: (ProviderStatus.ERROR, Reputation.UNAVAILABLE),
            401: (ProviderStatus.ERROR, Reputation.UNAVAILABLE),
            403: (ProviderStatus.ERROR, Reputation.UNAVAILABLE),
            404: (ProviderStatus.SUCCESS, Reputation.UNKNOWN),
            429: (ProviderStatus.UNAVAILABLE, Reputation.UNAVAILABLE),
            500: (ProviderStatus.ERROR, Reputation.UNAVAILABLE),
            502: (ProviderStatus.ERROR, Reputation.UNAVAILABLE),
        }
        for status_code, expected_result in expected.items():
            with self.subTest(status_code=status_code):
                provider = self.provider_for(
                    lambda request, status_code=status_code: httpx.Response(status_code)
                )
                result = provider.lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
                self.assertEqual((result.status, result.reputation), expected_result)
                self.assertNotEqual(result.reputation, Reputation.BENIGN)

    def test_timeout_and_connection_error_are_safe(self) -> None:
        for error in (httpx.ReadTimeout("timeout"), httpx.ConnectError("offline")):
            with self.subTest(error=type(error).__name__):
                def handler(request: httpx.Request, error: httpx.RequestError = error) -> httpx.Response:
                    error.request = request
                    raise error

                provider = self.provider_for(handler)
                result = provider.lookup(self.indicator(IndicatorType.IP, "8.8.8.8"))
                self.assertEqual(result.reputation, Reputation.UNAVAILABLE)
                self.assertIn(result.status, {ProviderStatus.UNAVAILABLE, ProviderStatus.ERROR})

    def test_response_parsing_and_reputation_mapping(self) -> None:
        provider = self.provider_for(self.success_response)
        result = provider.lookup(self.indicator(IndicatorType.HASH, "a" * 64))
        self.assertEqual(result.status, ProviderStatus.SUCCESS)
        self.assertEqual(result.reputation, Reputation.MALICIOUS)
        self.assertEqual(result.findings[0].metadata["analysis_statistics"]["malicious"], 2)
        self.assertIsNotNone(result.provider_reference)

        no_evidence = self.provider_for(
            lambda request: httpx.Response(
                200,
                json={"data": {"attributes": {"last_analysis_stats": {}}}},
            )
        ).lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        self.assertEqual(no_evidence.reputation, Reputation.UNKNOWN)
        self.assertEqual(no_evidence.status, ProviderStatus.SUCCESS)

    def test_missing_or_malformed_responses_are_safe(self) -> None:
        missing = self.provider_for(
            lambda request: httpx.Response(200, json={"data": {"attributes": {}}})
        ).lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        malformed = self.provider_for(
            lambda request: httpx.Response(200, json={"data": []})
        ).lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        invalid_json = self.provider_for(
            lambda request: httpx.Response(
                200,
                content=b"not valid json",
                headers={"content-type": "application/json"},
            )
        ).lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        self.assertEqual((missing.status, missing.reputation), (ProviderStatus.PARTIAL, Reputation.UNKNOWN))
        self.assertEqual((malformed.status, malformed.reputation), (ProviderStatus.ERROR, Reputation.UNAVAILABLE))
        self.assertEqual((invalid_json.status, invalid_json.reputation), (ProviderStatus.ERROR, Reputation.UNAVAILABLE))

    def test_api_key_is_not_exposed_in_result_data_or_errors(self) -> None:
        provider = self.provider_for(lambda request: httpx.Response(401))
        result = provider.lookup(self.indicator(IndicatorType.DOMAIN, "example.com"))
        serialized = result.model_dump_json()
        self.assertNotIn(self.api_key, serialized)
        self.assertNotIn(self.api_key, result.findings[0].description)


if __name__ == "__main__":
    unittest.main()
