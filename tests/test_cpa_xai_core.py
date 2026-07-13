"""Unit tests for CPA protocol helpers (no network / no browser)."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cpa_xai.errors import (
    BROWSER_FAIL,
    MISSING_EMAIL,
    PROBE_NO_GROK45,
    PROTOCOL_APPROVE,
    PROTOCOL_ONLY_FAIL,
    PROTOCOL_ONLY_NO_SSO,
    PROTOCOL_SSO_INVALID,
    PROTOCOL_VERIFY,
    classify_export_error,
    classify_protocol_message,
)
from cpa_xai.mint import mint_and_export
from cpa_xai.protocol_mint import extract_sso_from_cookies
from cpa_xai.schema import build_cpa_xai_auth, credential_file_name


def _fake_jwt(*, sub: str = "user-1", exp: int = 2_000_000_000, iat: int = 1_999_978_400) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": sub, "exp": exp, "iat": iat}).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}.sig"


class ExtractSsoTests(unittest.TestCase):
    def test_from_dict_prefers_sso(self):
        self.assertEqual(
            extract_sso_from_cookies({"sso-rw": "rw", "sso": "main"}),
            "main",
        )

    def test_from_list_prefers_bare_sso(self):
        cookies = [
            {"name": "sso-rw", "value": "rw-token"},
            {"name": "sso", "value": "sso-token"},
        ]
        self.assertEqual(extract_sso_from_cookies(cookies), "sso-token")

    def test_from_list_falls_back_to_sso_rw(self):
        cookies = [{"Name": "sso-rw", "Value": "only-rw"}]
        self.assertEqual(extract_sso_from_cookies(cookies), "only-rw")

    def test_empty(self):
        self.assertEqual(extract_sso_from_cookies(None), "")
        self.assertEqual(extract_sso_from_cookies([]), "")


class SchemaTests(unittest.TestCase):
    def test_credential_file_name_sanitizes(self):
        self.assertEqual(
            credential_file_name("a+b@Example.com"),
            "xai-a-b@Example.com.json",
        )

    def test_build_cpa_xai_auth_requires_refresh(self):
        with self.assertRaises(ValueError):
            build_cpa_xai_auth(
                email="a@b.com",
                access_token=_fake_jwt(),
                refresh_token="",
            )

    def test_build_cpa_xai_auth_fields(self):
        access = _fake_jwt(sub="sub-xyz")
        payload = build_cpa_xai_auth(
            email="u@x.ai",
            access_token=access,
            refresh_token="refresh-1",
        )
        self.assertEqual(payload["type"], "xai")
        self.assertEqual(payload["email"], "u@x.ai")
        self.assertEqual(payload["sub"], "sub-xyz")
        self.assertEqual(payload["refresh_token"], "refresh-1")
        self.assertTrue(payload["base_url"].endswith("/v1"))


class ErrorClassifyTests(unittest.TestCase):
    def test_protocol_messages(self):
        self.assertEqual(
            classify_protocol_message("sso invalid (landed https://.../sign-in)"),
            PROTOCOL_SSO_INVALID,
        )
        self.assertEqual(
            classify_protocol_message("device/verify failed status=403"),
            PROTOCOL_VERIFY,
        )
        self.assertEqual(
            classify_protocol_message("device/approve failed status=500"),
            PROTOCOL_APPROVE,
        )

    def test_export_errors(self):
        self.assertEqual(
            classify_export_error("protocol_only: boom", mint_method="protocol"),
            PROTOCOL_ONLY_FAIL,
        )
        self.assertEqual(
            classify_export_error("token ok but grok-4.5 not listed"),
            PROBE_NO_GROK45,
        )
        self.assertEqual(
            classify_export_error("click failed", mint_method="browser"),
            BROWSER_FAIL,
        )


class MintAndExportUnitTests(unittest.TestCase):
    def test_missing_email(self):
        with tempfile.TemporaryDirectory() as td:
            r = mint_and_export(email="", password="x", auth_dir=td, prefer_protocol=False)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_code"], MISSING_EMAIL)

    def test_protocol_only_without_sso(self):
        with tempfile.TemporaryDirectory() as td:
            r = mint_and_export(
                email="a@b.com",
                password="pw",
                auth_dir=td,
                prefer_protocol=True,
                protocol_only=True,
                sso="",
                cookies=None,
            )
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_code"], PROTOCOL_ONLY_NO_SSO)
        self.assertEqual(r["mint_method"], "protocol")

    def test_protocol_success_writes_file(self):
        tokens = {
            "access_token": _fake_jwt(sub="s1"),
            "refresh_token": "rt-1",
            "id_token": None,
            "expires_in": 3600,
            "user_code": "ABCD",
            "mint_method": "protocol",
        }

        def fake_protocol(**kwargs):
            return tokens

        with tempfile.TemporaryDirectory() as td:
            with patch("cpa_xai.mint.mint_with_sso_protocol", side_effect=fake_protocol):
                with patch(
                    "cpa_xai.mint.probe_models",
                    return_value={
                        "ok": True,
                        "status": 200,
                        "model_ids": ["grok-4.5"],
                        "has_grok_45": True,
                    },
                ):
                    r = mint_and_export(
                        email="ok@x.ai",
                        password="pw",
                        auth_dir=td,
                        sso="sso-cookie-value",
                        prefer_protocol=True,
                        probe=True,
                    )
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["mint_method"], "protocol")
            self.assertTrue(Path(r["path"]).is_file())
            data = json.loads(Path(r["path"]).read_text(encoding="utf-8"))
            self.assertEqual(data["email"], "ok@x.ai")
            self.assertEqual(data["refresh_token"], "rt-1")

    def test_protocol_fail_protocol_only(self):
        from cpa_xai.protocol_mint import ProtocolMintError

        with tempfile.TemporaryDirectory() as td:
            with patch(
                "cpa_xai.mint.mint_with_sso_protocol",
                side_effect=ProtocolMintError("device/verify failed status=403"),
            ):
                r = mint_and_export(
                    email="a@b.com",
                    password="pw",
                    auth_dir=td,
                    sso="sso",
                    prefer_protocol=True,
                    protocol_only=True,
                    probe=False,
                )
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_code"], PROTOCOL_ONLY_FAIL)
        self.assertEqual(r["protocol_error_code"], PROTOCOL_VERIFY)


class ChromiumPathsTests(unittest.TestCase):
    def test_candidates_non_empty(self):
        from chromium_paths import candidate_browser_paths

        paths = candidate_browser_paths()
        self.assertIsInstance(paths, list)
        self.assertGreater(len(paths), 0)


if __name__ == "__main__":
    unittest.main()
