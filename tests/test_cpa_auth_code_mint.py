from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from cpa_xai import auth_code_mint as auth


def _jwt(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.signature"


class _Response:
    def __init__(
        self,
        *,
        url: str = "",
        status: int = 200,
        text: str = "",
        data=None,
        headers=None,
    ):
        self.url = url
        self.status_code = status
        self.text = text
        self._data = data
        self.headers = dict(headers or {})

    def json(self):
        if self._data is None:
            raise ValueError("not json")
        return self._data


class _Cookies:
    def set(self, *args, **kwargs):
        return None


class _Session:
    def __init__(self, *, authorize_url: str = "", html: str = ""):
        self.proxies = {}
        self.cookies = _Cookies()
        self.authorize_url = authorize_url
        self.html = html
        self.closed = False
        self.get_calls = []
        self.post_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append(url)
        if url == "https://accounts.x.ai/":
            return _Response(url="https://accounts.x.ai/")
        if url.startswith(auth.OIDC_ISSUER + "/oauth2/authorize"):
            return _Response(url=self.authorize_url, text=self.html)
        return _Response(url=url, text="")

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        if url.endswith("/oauth2/token"):
            return _Response(
                url=url,
                data={
                    "access_token": _jwt({"referrer": "grok-build"}),
                    "refresh_token": "refresh-secret",
                    "expires_in": 3600,
                },
            )
        return _Response(url=url, text="no code")

    def close(self):
        self.closed = True


class AuthCodeMintTests(unittest.TestCase):
    def test_direct_authorize_callback_validates_state_and_closes_session(self):
        session = _Session(
            authorize_url="http://127.0.0.1:56121/callback?code=abc&state=fixed-state"
        )
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            result = auth.mint_with_sso_auth_code(sso_cookie="cookie")

        self.assertEqual(result["mint_method"], "auth_code")
        self.assertEqual(result["referrer"], "grok-build")
        self.assertTrue(session.closed)
        self.assertEqual(len(session.post_calls), 1)
        self.assertTrue(session.post_calls[0][0].endswith("/oauth2/token"))

    def test_callback_state_mismatch_fails_and_closes_session(self):
        session = _Session(
            authorize_url="http://127.0.0.1:56121/callback?code=abc&state=wrong"
        )
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "expected", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "state mismatch"):
                auth.mint_with_sso_auth_code(sso_cookie="cookie")
        self.assertTrue(session.closed)

    def test_consent_callback_location_is_parsed_without_localhost_request(self):
        session = _Session(
            authorize_url="https://accounts.x.ai/oauth2/consent",
            html='<script>createServerReference("1234567890abcdef1234567890abcdef12345678")</script>',
        )
        original_post = session.post

        def consent_post(url, **kwargs):
            session.post_calls.append((url, kwargs))
            if url.endswith("/oauth2/token"):
                return original_post(url, **kwargs)
            return _Response(
                url=url,
                status=303,
                headers={
                    "Location": "http://127.0.0.1:56121/callback?code=abc&state=fixed-state"
                },
            )

        session.post = consent_post
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            result = auth.mint_with_sso_auth_code(sso_cookie="cookie")

        self.assertEqual(result["mint_method"], "auth_code")
        self.assertFalse(any("127.0.0.1:56121" in url for url in session.get_calls))
        consent_call = next(
            kwargs for url, kwargs in session.post_calls if "/oauth2/consent" in url
        )
        self.assertFalse(consent_call["allow_redirects"])
        self.assertEqual(consent_call["headers"]["Origin"], "https://accounts.x.ai")

    def test_consent_remote_redirect_is_bounded_and_origin_uses_final_url(self):
        session = _Session(
            authorize_url="https://auth.x.ai/oauth2/consent",
            html='<script>createServerReference("1234567890abcdef1234567890abcdef12345678")</script>',
        )
        original_get = session.get
        original_post = session.post

        def consent_post(url, **kwargs):
            session.post_calls.append((url, kwargs))
            if url.endswith("/oauth2/token"):
                return original_post(url, **kwargs)
            return _Response(
                url=url,
                status=303,
                headers={"Location": "https://auth.x.ai/oauth2/intermediate"},
            )

        def remote_get(url, **kwargs):
            if url == "https://auth.x.ai/oauth2/intermediate":
                session.get_calls.append(url)
                return _Response(
                    url=url,
                    status=302,
                    headers={
                        "Location": "http://127.0.0.1:56121/callback?code=abc&state=fixed-state"
                    },
                )
            return original_get(url, **kwargs)

        session.post = consent_post
        session.get = remote_get
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            result = auth.mint_with_sso_auth_code(sso_cookie="cookie")

        self.assertEqual(result["mint_method"], "auth_code")
        self.assertIn("https://auth.x.ai/oauth2/intermediate", session.get_calls)
        self.assertFalse(any("127.0.0.1:56121" in url for url in session.get_calls))
        consent_call = next(
            kwargs for url, kwargs in session.post_calls if "/oauth2/consent" in url
        )
        self.assertFalse(consent_call["allow_redirects"])
        self.assertEqual(consent_call["headers"]["Origin"], "https://auth.x.ai")

    def test_consent_oauth_error_and_redirect_uri_mismatch_are_rejected(self):
        for callback, expected_error in (
            (
                "http://127.0.0.1:56121/callback?error=access_denied&state=fixed-state",
                "oauth callback error",
            ),
            (
                "http://127.0.0.1:56122/callback?code=abc&state=fixed-state",
                "redirect URI mismatch",
            ),
        ):
            with self.subTest(callback=callback):
                session = _Session(
                    authorize_url="https://accounts.x.ai/oauth2/consent",
                    html='<script>createServerReference("1234567890abcdef1234567890abcdef12345678")</script>',
                )
                original_post = session.post

                def consent_post(url, **kwargs):
                    session.post_calls.append((url, kwargs))
                    if url.endswith("/oauth2/token"):
                        return original_post(url, **kwargs)
                    return _Response(url=url, status=303, headers={"Location": callback})

                session.post = consent_post
                with (
                    patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
                    patch.object(auth.cf_requests, "Session", return_value=session),
                ):
                    with self.assertRaisesRegex(auth.AuthCodeMintError, expected_error):
                        auth.mint_with_sso_auth_code(sso_cookie="cookie")
                self.assertFalse(any("127.0.0.1:5612" in url for url in session.get_calls))

    def test_consent_does_not_follow_untrusted_redirect_host(self):
        session = _Session(
            authorize_url="https://accounts.x.ai/oauth2/consent",
            html='<script>createServerReference("1234567890abcdef1234567890abcdef12345678")</script>',
        )

        def consent_post(url, **kwargs):
            session.post_calls.append((url, kwargs))
            return _Response(
                url=url,
                status=302,
                headers={"Location": "https://example.invalid/collect"},
            )

        session.post = consent_post
        with patch.object(auth.cf_requests, "Session", return_value=session):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "consent failed"):
                auth.mint_with_sso_auth_code(sso_cookie="cookie")

        self.assertNotIn("https://example.invalid/collect", session.get_calls)

    def test_referrer_is_strict_by_default(self):
        session = _Session(
            authorize_url="http://127.0.0.1:56121/callback?code=abc&state=fixed-state"
        )

        def token_without_referrer(url, **kwargs):
            session.post_calls.append((url, kwargs))
            return _Response(
                url=url,
                data={
                    "access_token": _jwt({}),
                    "refresh_token": "refresh-secret",
                },
            )

        session.post = token_without_referrer
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "referrer"):
                auth.mint_with_sso_auth_code(sso_cookie="cookie")
        self.assertTrue(session.closed)

    def test_cli_proxy_api_referrer_is_rejected(self):
        session = _Session(
            authorize_url="http://127.0.0.1:56121/callback?code=abc&state=fixed-state"
        )

        def token_with_wrong_referrer(url, **kwargs):
            return _Response(
                url=url,
                data={
                    "access_token": _jwt({"referrer": "cli-proxy-api"}),
                    "refresh_token": "refresh-secret",
                },
            )

        session.post = token_with_wrong_referrer
        with (
            patch.object(auth, "_gen_pkce", return_value=("verifier", "challenge", "fixed-state", "nonce")),
            patch.object(auth.cf_requests, "Session", return_value=session),
        ):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "referrer"):
                auth.mint_with_sso_auth_code(sso_cookie="cookie")
        self.assertTrue(session.closed)

    def test_total_timeout_is_checked_before_network_and_closes_session(self):
        session = _Session()
        with (
            patch.object(auth.cf_requests, "Session", return_value=session),
            patch.object(auth.time, "monotonic", side_effect=[0.0, 1.0]),
        ):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "total timeout"):
                auth.mint_with_sso_auth_code(
                    sso_cookie="cookie", total_timeout_sec=0.01
                )
        self.assertEqual(session.get_calls, [])
        self.assertTrue(session.closed)

    def test_js_discovery_scans_at_most_eight_chunks(self):
        session = _Session()
        html = "".join(f'<script src="/_next/chunk-{i}.js"></script>' for i in range(20))
        auth._discover_action_ids_from_js(session, html, max_chunks=8)
        self.assertEqual(len(session.get_calls), 8)

    def test_consent_attempts_at_most_five_action_ids(self):
        actions = "".join(
            f'createServerReference("{i:040x}")' for i in range(1, 9)
        )
        scripts = "".join(f'<script src="/_next/chunk-{i}.js"></script>' for i in range(12))
        session = _Session(
            authorize_url="https://accounts.x.ai/oauth2/consent",
            html=actions + scripts,
        )
        with patch.object(auth.cf_requests, "Session", return_value=session):
            with self.assertRaisesRegex(auth.AuthCodeMintError, "5 Next-Action"):
                auth.mint_with_sso_auth_code(sso_cookie="cookie")
        consent_posts = [url for url, _ in session.post_calls if "/oauth2/consent" in url]
        self.assertEqual(len(consent_posts), 5)
        self.assertLessEqual(
            len([url for url in session.get_calls if "/_next/" in url]),
            8,
        )
        self.assertTrue(session.closed)

    def test_error_redaction_removes_sensitive_query_values_and_jwt(self):
        message = auth._redact_error(
            "https://x/callback?code=secret&state=private token=aaa.bbbbbbbb.cccccccc"
        )
        self.assertNotIn("secret", message)
        self.assertNotIn("private", message)
        self.assertNotIn("aaa.bbbbbbbb.cccccccc", message)


if __name__ == "__main__":
    unittest.main()
