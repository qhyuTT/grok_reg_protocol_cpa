from __future__ import annotations

import json
import unittest

from cpa_xai.inspection import (
    aggregate_health_attempts,
    classify_probe,
    inspect_access_token,
    pick_model,
)
from cpa_xai.schema import DEFAULT_CLIENT_HEADERS


class _Response:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._raw = json.dumps(body).encode()

    def read(self):
        return self._raw

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _HTTPErrorResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._raw = json.dumps(body).encode()

    def read(self):
        return self._raw

    def close(self):
        return None


class _Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
        self.requests = []
        self.bodies = []

    def open(self, request, timeout=0):
        self.urls.append(request.full_url)
        self.requests.append(request)
        self.bodies.append(request.data)
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def _http_error(status, body):
    import urllib.error

    return urllib.error.HTTPError("https://test", status, "error", {}, _HTTPErrorResponse(status, body))


def test_pick_model_prefers_build_free_then_fallback():
    assert pick_model({"data": [{"id": "grok-3-mini"}, {"id": "grok-4.5-build-free"}]}) == "grok-4.5-build-free"
    assert pick_model({"data": [{"id": "custom"}]}) == "custom"
    assert pick_model({"data": []}) == "grok-4.5"


def test_permission_denied_keywords_and_status():
    generic_forbidden = classify_probe(403)
    assert generic_forbidden["classification"] == "forbidden_unknown"
    assert generic_forbidden["action"] == "keep"
    assert classify_probe(200, code="permission-denied")["classification"] == "permission_denied"
    assert classify_probe(200, error="chat endpoint is denied")["classification"] == "permission_denied"
    assert classify_probe(401)["classification"] == "reauth"
    assert classify_probe(429)["classification"] == "quota_exhausted"
    assert classify_probe(403, error="unauthorized")["classification"] == "reauth"
    assert classify_probe(402, error="limit reached")["classification"] == "quota_exhausted"


def test_responses_success_is_healthy_and_selects_model():
    opener = _Opener([
        _Response(200, {"data": [{"id": "grok-4.5-build-free"}]}),
        _Response(200, {"model": "grok-4.5-build-free", "output": []}),
    ])
    result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
    assert result["classification"] == "healthy"
    assert result["ok"] is True
    assert result["model"] == "grok-4.5-build-free"
    assert opener.urls == ["https://test/v1/models", "https://test/v1/responses"]
    assert json.loads(opener.bodies[1]) == {"model": "grok-4.5-build-free", "stream": False, "input": "ping"}


def test_main_permission_denied_with_healthy_fallback_is_inconsistent():
    opener = _Opener([
        _Response(200, {"data": [{"id": "grok-4.5"}]}),
        _Response(403, {"error": {"code": "permission-denied", "message": "chat denied"}}),
        _Response(200, {"model": "grok-4.5", "output": []}),
    ])
    result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
    assert result["classification"] == "endpoint_inconsistent"
    assert result["http_status"] == 403
    assert result["fallback_status"] == 200
    assert opener.urls[-1].endswith("/chat/completions")


def test_main_429_is_quota_authoritative_and_fallback_called():
    opener = _Opener([
        _Response(200, {"data": [{"id": "grok-4"}]}),
        _Response(429, {"error": {"code": "free-usage-exhausted", "message": "limit reached"}}),
        _http_error(403, {"error": {"code": "permission-denied"}}),
    ])
    result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
    assert result["classification"] == "quota_exhausted"
    assert result["http_status"] == 429


def test_main_quota_and_reauth_remain_authoritative_when_fallback_succeeds():
    for status, body, expected in (
        (
            429,
            {"error": {"code": "free-usage-exhausted", "message": "limit reached"}},
            "quota_exhausted",
        ),
        (401, {"error": {"message": "unauthorized"}}, "reauth"),
    ):
        opener = _Opener([
            _Response(200, {"data": [{"id": "grok-4"}]}),
            _Response(status, body),
            _Response(200, {"model": "grok-4", "output": []}),
        ])
        result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
        assert result["classification"] == expected
        assert result["http_status"] == status
        assert result["fallback_status"] == 200


def test_models_failure_still_probes_chat_endpoint():
    opener = _Opener([
        _http_error(403, {"error": {"code": "permission-denied"}}),
        _Response(200, {"output": []}),
    ])
    result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
    assert result["classification"] == "healthy"
    assert result["models_status"] == 403
    assert result["model"] == "grok-4.5"
    assert len(opener.urls) == 2


class InspectionTests(unittest.TestCase):
    def test_pick_model(self):
        test_pick_model_prefers_build_free_then_fallback()

    def test_permission_classification(self):
        test_permission_denied_keywords_and_status()

    def test_responses_success(self):
        test_responses_success_is_healthy_and_selects_model()

    def test_primary_permission_is_authoritative(self):
        test_main_permission_denied_with_healthy_fallback_is_inconsistent()

    def test_primary_quota_is_authoritative(self):
        test_main_429_is_quota_authoritative_and_fallback_called()

    def test_primary_quota_and_reauth_ignore_healthy_fallback(self):
        test_main_quota_and_reauth_remain_authoritative_when_fallback_succeeds()

    def test_models_failure_still_probes_chat(self):
        test_models_failure_still_probes_chat_endpoint()

    def test_inspection_headers_match_reference_client(self):
        opener = _Opener([
            _Response(200, {"data": [{"id": "grok-4.5"}]}),
            _Response(200, {"output": []}),
        ])
        result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
        headers = {key.lower(): value for key, value in opener.requests[-1].header_items()}
        for key, value in DEFAULT_CLIENT_HEADERS.items():
            self.assertEqual(headers[key.lower()], value)
        self.assertEqual(
            result["headers_profile"]["client_identifier"],
            DEFAULT_CLIENT_HEADERS["x-grok-client-identifier"],
        )

    def test_all_generic_403_endpoints_are_egress_access_denied(self):
        opener = _Opener([
            _http_error(403, {}),
            _http_error(403, {}),
            _http_error(403, {}),
        ])
        result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
        self.assertEqual(result["classification"], "egress_access_denied")
        self.assertEqual(result["confidence"], "inconclusive")

    def test_explicit_permission_evidence_is_not_mislabeled_as_egress(self):
        opener = _Opener([
            _http_error(403, {}),
            _http_error(403, {"error": {"code": "permission-denied"}}),
            _http_error(403, {}),
        ])
        result = inspect_access_token("token", base_url="https://test/v1", opener=opener)
        self.assertEqual(result["classification"], "permission_denied")

    def test_repeated_permission_requires_confirmed_evidence(self):
        attempts = [
            {
                "classification": "permission_denied",
                "confidence": "confirmed",
                "http_status": 403,
                "error_code": "permission-denied",
            }
            for _ in range(3)
        ]
        result = aggregate_health_attempts(attempts)
        self.assertTrue(result["reject_candidate"])
        self.assertEqual(result["classification"], "permission_denied")

    def test_single_permission_result_is_not_treated_as_repeated_confirmation(self):
        result = aggregate_health_attempts(
            [
                {
                    "classification": "permission_denied",
                    "confidence": "confirmed",
                    "http_status": 403,
                    "error_code": "permission-denied",
                }
            ]
        )
        self.assertFalse(result["reject_candidate"])

    def test_any_healthy_retry_wins(self):
        result = aggregate_health_attempts(
            [
                {"classification": "forbidden_unknown", "http_status": 403},
                {"classification": "healthy", "http_status": 200, "ok": True},
            ]
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["reject_candidate"])

    def test_repeated_reauth_is_rejected_with_confirmed_confidence(self):
        result = aggregate_health_attempts(
            [
                {
                    "classification": "reauth",
                    "confidence": "confirmed",
                    "http_status": 401,
                }
                for _ in range(3)
            ]
        )
        self.assertTrue(result["reject_candidate"])
        self.assertEqual(result["classification"], "reauth")
        self.assertEqual(result["confidence"], "confirmed")

    def test_repeated_generic_forbidden_is_rejected(self):
        result = aggregate_health_attempts(
            [
                {
                    "classification": "forbidden_unknown",
                    "confidence": "inconclusive",
                    "http_status": 403,
                }
                for _ in range(3)
            ]
        )
        self.assertTrue(result["reject_candidate"])
        self.assertEqual(result["classification"], "forbidden_unknown")

    def test_repeated_egress_access_denied_obeys_reject_inconclusive(self):
        attempts = [
            {
                "classification": "egress_access_denied",
                "confidence": "inconclusive",
                "http_status": 403,
            }
            for _ in range(3)
        ]
        rejected = aggregate_health_attempts(attempts, reject_inconclusive=True)
        retained = aggregate_health_attempts(attempts, reject_inconclusive=False)
        self.assertTrue(rejected["reject_candidate"])
        self.assertEqual(rejected["reject_reason"], "egress_access_denied")
        self.assertFalse(retained["reject_candidate"])

    def test_single_forbidden_followed_by_network_errors_is_not_rejected(self):
        result = aggregate_health_attempts(
            [
                {"classification": "forbidden_unknown", "http_status": 403},
                {"classification": "probe_error", "http_status": 0},
                {"classification": "probe_error", "http_status": 0},
            ]
        )
        self.assertFalse(result["reject_candidate"])
        self.assertEqual(result["classification"], "probe_error")


if __name__ == "__main__":
    unittest.main()
