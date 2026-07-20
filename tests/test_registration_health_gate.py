from __future__ import annotations

import base64
import json
import tempfile
import queue
import unittest
from pathlib import Path
from unittest.mock import call, patch

import cpa_xai
import cpa_xai.mint as mint_module
import cpa_export
import register_cli


def _jwt(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.signature"


class MintHealthGateTests(unittest.TestCase):
    def _mint_tokens(self) -> dict[str, object]:
        return {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
            "mint_method": "protocol",
            "referrer": "grok-build",
        }

    def test_permission_denied_does_not_write_auth_or_return_path(self):
        health = {
            "classification": "permission_denied",
            "confidence": "confirmed",
            "http_status": 403,
            "error_code": "permission-denied",
            "reason": "chat endpoint is denied",
        }
        with (
            patch.object(mint_module, "mint_with_sso_protocol", return_value=self._mint_tokens()),
            patch("cpa_xai.inspection.inspect_access_token", return_value=health),
            patch.object(mint_module, "write_cpa_xai_auth") as writer,
        ):
            result = cpa_xai.mint_and_export(
                email="denied@example.com",
                password="secret",
                auth_dir="unused-auth-dir",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                health_probe_delays=(0, 0.001),
                probe=False,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["rejected"])
        self.assertEqual(result["health"]["classification"], "permission_denied")
        self.assertTrue(result["health"]["reject_candidate"])
        self.assertEqual(len(result["health"]["attempts"]), 2)
        self.assertNotIn("path", result)
        writer.assert_not_called()

    def test_probe_error_is_kept_and_auth_is_written(self):
        health = {
            "classification": "probe_error",
            "http_status": 500,
            "error_message": "temporary upstream failure",
        }
        expected_path = Path("/tmp/xai-probe-error@example.com.json")
        with (
            patch.object(mint_module, "mint_with_sso_protocol", return_value=self._mint_tokens()),
            patch("cpa_xai.inspection.inspect_access_token", return_value=health),
            patch.object(mint_module, "write_cpa_xai_auth", return_value=expected_path) as writer,
        ):
            result = cpa_xai.mint_and_export(
                email="probe-error@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                health_probe_delays=(0,),
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("rejected", result)
        self.assertEqual(result["health"]["classification"], "probe_error")
        self.assertFalse(result["health"]["reject_candidate"])
        self.assertEqual(result["path"], str(expected_path))
        writer.assert_called_once()

    def test_export_passes_strict_auth_code_defaults_and_timeout(self):
        with tempfile.TemporaryDirectory() as tempdir, patch.object(
            cpa_xai,
            "mint_and_export",
            return_value={"ok": True},
        ) as mint:
            cpa_export.export_cpa_xai_for_account(
                "user@example.com",
                "secret",
                sso="sso-cookie",
                config={
                    "cpa_auth_dir": tempdir,
                    "cpa_probe_after_write": False,
                },
                log_callback=lambda _message: None,
            )

        kwargs = mint.call_args.kwargs
        self.assertEqual(kwargs["auth_code_timeout_sec"], 90.0)
        self.assertTrue(kwargs["auth_code_require_referrer"])
        self.assertEqual(kwargs["required_referrer"], "grok-build")
        self.assertTrue(kwargs["skip_device_when_referrer_required"])
        self.assertEqual(kwargs["health_probe_delays"], [10.0, 20.0, 45.0])
        self.assertEqual(
            register_cli.reg.DEFAULT_CONFIG["registration_health_probe_delays_sec"],
            [10, 20, 45],
        )

    def test_health_delay_parser_defaults_and_preserves_explicit_legacy_offsets(self):
        self.assertEqual(cpa_export._parse_health_delays(None), [10.0, 20.0, 45.0])
        self.assertEqual(cpa_export._parse_health_delays([]), [10.0, 20.0, 45.0])
        self.assertEqual(
            cpa_export._parse_health_delays([0, 15, 45]),
            [0.0, 15.0, 45.0],
        )

    def test_default_schedule_waits_until_ten_seconds_and_records_token_age(self):
        token = {
            "access_token": _jwt({"iat": 1000, "referrer": "grok-build"}),
            "refresh_token": "refresh-token",
            "expires_in": 3600,
            "mint_method": "protocol",
        }
        logs: list[str] = []
        with (
            patch.object(mint_module, "mint_with_sso_protocol", return_value=token),
            patch.object(mint_module, "_wait_with_cancel", return_value=True) as wait,
            patch.object(mint_module.time, "monotonic", side_effect=[0.0, 0.0]),
            patch.object(mint_module.time, "time", return_value=1012.5),
            patch(
                "cpa_xai.inspection.inspect_access_token",
                return_value={"classification": "healthy", "confidence": "confirmed"},
            ) as inspect,
        ):
            result = cpa_xai.mint_and_export(
                email="schedule@example.com",
                password="secret",
                auth_dir="unused",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                write_auth=False,
                probe=False,
                log=logs.append,
            )

        self.assertTrue(result["ok"])
        wait.assert_called_once_with(10.0, None)
        inspect.assert_called_once()
        attempt = result["health"]["attempts"][0]
        self.assertEqual(attempt["offset_sec"], 10.0)
        self.assertEqual(attempt["token_age_sec"], 12.5)
        self.assertTrue(any("offset=10.0s token_age=12.500s" in row for row in logs))

    def test_default_schedule_uses_absolute_ten_twenty_forty_five_offsets(self):
        denied = {
            "classification": "permission_denied",
            "confidence": "confirmed",
            "http_status": 403,
            "error_code": "permission-denied",
        }
        with (
            patch.object(mint_module, "mint_with_sso_protocol", return_value=self._mint_tokens()),
            patch.object(mint_module, "_wait_with_cancel", return_value=True) as wait,
            patch.object(
                mint_module.time,
                "monotonic",
                side_effect=[0.0, 0.0, 10.0, 20.0],
            ),
            patch(
                "cpa_xai.inspection.inspect_access_token",
                side_effect=[dict(denied) for _ in range(3)],
            ) as inspect,
        ):
            result = cpa_xai.mint_and_export(
                email="persistent-denied@example.com",
                password="secret",
                auth_dir="unused",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                write_auth=False,
                probe=False,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["rejected"])
        self.assertEqual(
            wait.call_args_list,
            [call(10.0, None), call(10.0, None), call(25.0, None)],
        )
        self.assertEqual(inspect.call_count, 3)
        self.assertEqual(
            [row["offset_sec"] for row in result["health"]["attempts"]],
            [10.0, 20.0, 45.0],
        )

    def test_default_schedule_stops_after_twenty_or_forty_five_second_success(self):
        denied = {
            "classification": "permission_denied",
            "confidence": "confirmed",
            "http_status": 403,
            "error_code": "permission-denied",
        }
        healthy = {"classification": "healthy", "confidence": "confirmed"}
        scenarios = (
            (
                "healthy_at_twenty",
                [dict(denied), dict(healthy)],
                [0.0, 0.0, 10.0],
                [call(10.0, None), call(10.0, None)],
                [10.0, 20.0],
            ),
            (
                "healthy_at_forty_five",
                [dict(denied), dict(denied), dict(healthy)],
                [0.0, 0.0, 10.0, 20.0],
                [call(10.0, None), call(10.0, None), call(25.0, None)],
                [10.0, 20.0, 45.0],
            ),
        )
        for name, health_rows, monotonic_values, waits, offsets in scenarios:
            with self.subTest(name=name):
                with (
                    patch.object(
                        mint_module,
                        "mint_with_sso_protocol",
                        return_value=self._mint_tokens(),
                    ),
                    patch.object(
                        mint_module, "_wait_with_cancel", return_value=True
                    ) as wait,
                    patch.object(
                        mint_module.time,
                        "monotonic",
                        side_effect=monotonic_values,
                    ),
                    patch(
                        "cpa_xai.inspection.inspect_access_token",
                        side_effect=health_rows,
                    ),
                ):
                    result = cpa_xai.mint_and_export(
                        email=f"{name}@example.com",
                        password="secret",
                        auth_dir="unused",
                        sso="sso-cookie",
                        prefer_auth_code=False,
                        skip_device_when_referrer_required=False,
                        health_check=True,
                        write_auth=False,
                        probe=False,
                    )

                self.assertTrue(result["ok"])
                self.assertEqual(wait.call_args_list, waits)
                self.assertEqual(
                    [row["offset_sec"] for row in result["health"]["attempts"]],
                    offsets,
                )

    def test_invalid_protocol_referrer_falls_back_to_browser_when_device_allowed(
        self,
    ):
        """Legacy path: skip_device=false still allows protocol→browser fallback."""
        browser_tokens = {
            "access_token": "browser-access",
            "refresh_token": "browser-refresh",
            "expires_in": 3600,
            "referrer": "grok-build",
        }
        health = {"classification": "healthy", "confidence": "confirmed"}
        expected_path = Path("/tmp/xai-referrer-fallback@example.com.json")
        with (
            patch.object(
                mint_module,
                "mint_with_sso_protocol",
                return_value={
                    "access_token": "protocol-access",
                    "refresh_token": "protocol-refresh",
                    "expires_in": 3600,
                    "mint_method": "protocol",
                },
            ),
            patch.object(mint_module, "mint_with_browser", return_value=browser_tokens),
            patch("cpa_xai.inspection.inspect_access_token", return_value=health) as inspect,
            patch.object(mint_module, "write_cpa_xai_auth", return_value=expected_path) as writer,
        ):
            result = cpa_xai.mint_and_export(
                email="referrer-fallback@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                health_probe_delays=(0,),
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["mint_method"], "browser")
        self.assertIn("referrer", result["protocol_error"])
        inspect.assert_called_once()
        writer.assert_called_once()

    def test_invalid_auth_code_referrer_aborts_device_under_default_policy(self):
        logs: list[str] = []
        with (
            patch.object(
                mint_module,
                "mint_with_sso_auth_code",
                return_value={
                    "access_token": "auth-code-access",
                    "refresh_token": "auth-code-refresh",
                    "expires_in": 3600,
                    "mint_method": "auth_code",
                },
            ) as auth_code_mint,
            patch.object(mint_module, "mint_with_sso_protocol") as protocol_mint,
            patch.object(mint_module, "mint_with_browser") as browser_mint,
            patch.object(mint_module, "write_cpa_xai_auth") as writer,
        ):
            result = cpa_xai.mint_and_export(
                email="auth-code-abort@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                probe=False,
                log=logs.append,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result.get("skipped_device"))
        self.assertIn("referrer", result["auth_code_error"] or "")
        self.assertIn("device flows cannot satisfy", result["error"])
        self.assertIn("auth_code failed", result["error"])
        auth_code_mint.assert_called_once()
        protocol_mint.assert_not_called()
        browser_mint.assert_not_called()
        writer.assert_not_called()
        self.assertTrue(any("mint abort:" in row for row in logs))

    def test_auth_code_error_aborts_device_under_referrer_policy(self):
        with (
            patch.object(
                mint_module,
                "mint_with_sso_auth_code",
                side_effect=mint_module.AuthCodeMintError(
                    "consent failed after 2 Next-Action tries: consent HTTP 404"
                ),
            ),
            patch.object(mint_module, "mint_with_sso_protocol") as protocol_mint,
            patch.object(mint_module, "mint_with_browser") as browser_mint,
        ):
            result = cpa_xai.mint_and_export(
                email="consent-404@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                probe=False,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result.get("skipped_device"))
        self.assertIn("consent HTTP 404", result["error"])
        self.assertIn("consent HTTP 404", result["auth_code_error"] or "")
        protocol_mint.assert_not_called()
        browser_mint.assert_not_called()

    def test_invalid_auth_code_referrer_falls_back_when_device_allowed(self):
        expected_path = Path("/tmp/xai-auth-code-fallback@example.com.json")
        with (
            patch.object(
                mint_module,
                "mint_with_sso_auth_code",
                return_value={
                    "access_token": "auth-code-access",
                    "refresh_token": "auth-code-refresh",
                    "expires_in": 3600,
                    "mint_method": "auth_code",
                },
            ) as auth_code_mint,
            patch.object(
                mint_module,
                "mint_with_sso_protocol",
                return_value=self._mint_tokens(),
            ) as protocol_mint,
            patch.object(mint_module, "write_cpa_xai_auth", return_value=expected_path),
        ):
            result = cpa_xai.mint_and_export(
                email="auth-code-fallback@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                skip_device_when_referrer_required=False,
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["mint_method"], "protocol")
        self.assertIn("referrer", result["auth_code_error"])
        auth_code_mint.assert_called_once()
        protocol_mint.assert_called_once()

    def test_empty_referrer_policy_allows_device_after_auth_code_fail(self):
        expected_path = Path("/tmp/xai-empty-referrer@example.com.json")
        with (
            patch.object(
                mint_module,
                "mint_with_sso_auth_code",
                side_effect=mint_module.AuthCodeMintError("consent failed"),
            ),
            patch.object(
                mint_module,
                "mint_with_sso_protocol",
                return_value={
                    "access_token": "protocol-access",
                    "refresh_token": "protocol-refresh",
                    "expires_in": 3600,
                    "mint_method": "protocol",
                },
            ) as protocol_mint,
            patch.object(mint_module, "write_cpa_xai_auth", return_value=expected_path),
        ):
            result = cpa_xai.mint_and_export(
                email="empty-policy@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                required_referrer="",
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["mint_method"], "protocol")
        protocol_mint.assert_called_once()

    def test_invalid_referrer_is_rejected_without_health_or_write(self):
        with (
            patch.object(
                mint_module,
                "mint_with_sso_protocol",
                return_value={
                    "access_token": "protocol-access",
                    "refresh_token": "protocol-refresh",
                    "expires_in": 3600,
                    "mint_method": "protocol",
                },
            ),
            patch.object(
                mint_module,
                "mint_with_browser",
                return_value={
                    "access_token": "browser-access",
                    "refresh_token": "browser-refresh",
                    "expires_in": 3600,
                },
            ),
            patch("cpa_xai.inspection.inspect_access_token") as inspect,
            patch.object(mint_module, "write_cpa_xai_auth") as writer,
        ):
            result = cpa_xai.mint_and_export(
                email="referrer-rejected@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                prefer_auth_code=False,
                skip_device_when_referrer_required=False,
                health_check=True,
                probe=False,
            )

        self.assertFalse(result["ok"])
        self.assertIn("referrer", result["error"])
        inspect.assert_not_called()
        writer.assert_not_called()

    def test_legacy_referrer_switch_can_disable_pipeline_policy(self):
        health = {"classification": "healthy", "confidence": "confirmed"}
        expected_path = Path("/tmp/xai-referrer-disabled@example.com.json")
        with (
            patch.object(
                mint_module,
                "mint_with_sso_protocol",
                return_value={
                    "access_token": "protocol-access",
                    "refresh_token": "protocol-refresh",
                    "expires_in": 3600,
                    "mint_method": "protocol",
                },
            ),
            patch("cpa_xai.inspection.inspect_access_token", return_value=health),
            patch.object(mint_module, "write_cpa_xai_auth", return_value=expected_path),
        ):
            result = cpa_xai.mint_and_export(
                email="referrer-disabled@example.com",
                password="secret",
                auth_dir="auth-dir",
                sso="sso-cookie",
                prefer_auth_code=False,
                auth_code_require_referrer=False,
                health_check=True,
                health_probe_delays=(0,),
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["mint_method"], "protocol")

    def test_new_required_referrer_config_overrides_legacy_switch(self):
        with tempfile.TemporaryDirectory() as tempdir, patch.object(
            cpa_xai,
            "mint_and_export",
            return_value={"ok": True},
        ) as mint:
            cpa_export.export_cpa_xai_for_account(
                "user@example.com",
                "secret",
                sso="sso-cookie",
                config={
                    "cpa_auth_dir": tempdir,
                    "cpa_probe_after_write": False,
                    "cpa_auth_code_require_referrer": True,
                    "cpa_required_referrer": "",
                },
                log_callback=lambda _message: None,
            )

        self.assertEqual(mint.call_args.kwargs["required_referrer"], "")


class FinalizeCandidateHealthGateTests(unittest.TestCase):
    def _job(self, email: str) -> dict[str, object]:
        return {
            "email": email,
            "password": "secret",
            "sso": "sso-cookie",
            "cookies": [],
        }

    def test_rejected_candidate_is_not_written_and_is_marked_error(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("denied@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": False,
                        "rejected": True,
                        "rejection_summary": "permission_denied:http=403:code=permission-denied:attempts=3",
                        "health": {"classification": "permission_denied"},
                    },
                    str(accounts_path),
                )

            self.assertEqual(outcome, "rejected")
            self.assertFalse(accounts_path.exists())
            mark_error.assert_called_once_with(
                "denied@example.com",
                "secret",
                reason="permission_denied:http=403:code=permission-denied:attempts=3",
            )
            mark_used.assert_not_called()
            add_to_pool.assert_not_called()

    def test_healthy_with_cpa_path_is_accepted(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            email = "healthy@example.com"
            job = self._job(email)
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": True,
                        "path": "/tmp/xai-healthy@example.com.json",
                        "health": {"classification": "healthy"},
                    },
                    str(accounts_path),
                    require_cpa_file=True,
                    require_healthy=True,
                )

            self.assertEqual(outcome, "accepted")
            self.assertEqual(
                accounts_path.read_text(encoding="utf-8"),
                f"{email}----secret----sso-cookie\n",
            )
            mark_error.assert_not_called()
            mark_used.assert_called_once_with(email, "secret")
            add_to_pool.assert_called_once()

    def test_unknown_without_path_is_not_accepted_under_strict_policy(self):
        """Mint failed → no health → used to fake 'unknown success'; must fail now."""
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("ghost@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": False,
                        "error": "auth_code failed",
                        "auth_code_error": "consent HTTP 404",
                    },
                    str(accounts_path),
                    require_cpa_file=True,
                    require_healthy=True,
                )

            self.assertEqual(outcome, "failed")
            self.assertFalse(accounts_path.exists())
            mark_error.assert_called_once()
            mark_used.assert_not_called()
            add_to_pool.assert_not_called()

    def test_unknown_classification_with_path_rejected_when_healthy_required(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("soft@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": True,
                        "path": "/tmp/xai-soft@example.com.json",
                        "health": {"classification": "unknown"},
                    },
                    str(accounts_path),
                    require_cpa_file=True,
                    require_healthy=True,
                )

            self.assertEqual(outcome, "failed")
            self.assertFalse(accounts_path.exists())
            mark_error.assert_called_once()
            mark_used.assert_not_called()
            add_to_pool.assert_not_called()

    def test_legacy_soft_policy_can_keep_unknown_with_path(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("legacy@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": True,
                        "path": "/tmp/xai-legacy@example.com.json",
                        "health": {"classification": "unknown"},
                    },
                    str(accounts_path),
                    require_cpa_file=True,
                    require_healthy=False,
                )

            self.assertEqual(outcome, "accepted")
            self.assertTrue(accounts_path.exists())
            mark_error.assert_not_called()
            mark_used.assert_called_once()
            add_to_pool.assert_called_once()

    def test_mint_required_blocks_account_write_on_mint_fail(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("mint-fail@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": False,
                        "error": "auth_code failed and device flows cannot satisfy",
                        "auth_code_error": "consent HTTP 404",
                        "skipped_device": True,
                    },
                    str(accounts_path),
                    mint_required=True,
                    require_cpa_file=False,
                    require_healthy=False,
                )

            self.assertEqual(outcome, "failed")
            self.assertFalse(accounts_path.exists())
            mark_error.assert_called_once()
            mark_used.assert_not_called()
            add_to_pool.assert_not_called()

    def test_mint_fail_still_writes_only_when_policy_fully_relaxed(self):
        with tempfile.TemporaryDirectory() as tempdir:
            accounts_path = Path(tempdir) / "accounts.txt"
            job = self._job("mint-soft@example.com")
            with (
                patch.object(register_cli, "log"),
                patch.object(register_cli.reg, "mark_error") as mark_error,
                patch.object(register_cli.reg, "mark_used") as mark_used,
                patch.object(register_cli.reg, "add_token_to_grok2api_pools") as add_to_pool,
            ):
                outcome = register_cli._finalize_candidate(
                    1,
                    job,
                    {
                        "ok": False,
                        "error": "auth_code failed",
                        "auth_code_error": "consent HTTP 404",
                    },
                    str(accounts_path),
                    mint_required=False,
                    require_cpa_file=False,
                    require_healthy=False,
                )

            self.assertEqual(outcome, "accepted")
            self.assertTrue(accounts_path.exists())
            mark_error.assert_not_called()
            mark_used.assert_called_once()
            add_to_pool.assert_called_once()


class WebActivationReplacementTests(unittest.TestCase):
    def test_activation_failure_is_emitted_as_retryable_candidate_outcome(self):
        task_queue = queue.Queue()
        outcome_queue = queue.Queue()
        task_queue.put({"idx": 1, "slot": 1, "replacement": 0})
        task_queue.put(register_cli._TASK_STOP)
        register_cli._REGISTER_STOP.clear()
        register_cli._REGISTER_CAPACITY_STOP.clear()
        register_cli._SCHEDULER_DONE.clear()
        with (
            patch.dict(register_cli.reg.config, {"proxy_rotation_enabled": False}, clear=False),
            patch.object(
                register_cli,
                "register_one",
                side_effect=register_cli.reg.ActivationFailedRegistration(
                    "candidate@example.com", "set_birth_date_http_403"
                ),
            ) as register_one,
            patch.object(register_cli.reg, "stop_browser"),
        ):
            register_cli._register_worker(
                worker_id=1,
                task_queue=task_queue,
                total=1,
                accounts_file="unused.txt",
                mint_queue=None,
                forever=False,
                do_mint_inline=False,
                outcome_queue=outcome_queue,
            )

        self.assertEqual(register_one.call_count, 1)
        self.assertEqual(outcome_queue.get_nowait()["status"], "activation_failed")


class HealthAuditTests(unittest.TestCase):
    def test_rejected_health_audit_is_written_and_redacted(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "health.jsonl"
            result = {
                "mint_method": "protocol",
                "proxy": "http://proxy.invalid:7890",
                "token_metadata": {"scope": "grok-cli:access", "sub_hash": "abc"},
                "health": {
                    "classification": "forbidden_unknown",
                    "confidence": "inconclusive",
                    "reject_candidate": True,
                    "reject_reason": "forbidden_unknown",
                    "reason": "generic forbidden",
                    "attempts": [
                        {
                            "attempt": 1,
                            "offset_sec": 0,
                            "token_age_sec": 12.5,
                            "classification": "forbidden_unknown",
                            "http_status": 403,
                            "responses_raw_snippet": (
                                "email=user@example.com token="
                                "eyJaaaaaaaaaaaaaaaaaaaa.eyJbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccc"
                            ),
                        }
                    ],
                },
            }
            cpa_export._write_health_audit(
                result=result,
                email="user@example.com",
                cfg={"registration_health_audit_file": str(path)},
                log=lambda _message: None,
            )

            record = json.loads(path.read_text(encoding="utf-8"))
            raw = record["attempts"][0]["responses_raw_snippet"]
            self.assertNotIn("user@example.com", raw)
            self.assertNotIn("eyJaaaaaaaa", raw)
            self.assertEqual(record["attempts"][0]["token_age_sec"], 12.5)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_health_audit_redacts_long_token_before_truncation(self):
        token = f"{'a' * 220}.{'b' * 220}.{'c' * 220}"
        redacted = cpa_export._redact_audit_text(
            f'authorization=Bearer {token} access_token="opaque-secret"',
            limit=120,
        )
        self.assertNotIn("a" * 20, redacted)
        self.assertNotIn("opaque-secret", redacted)
        self.assertIn("<redacted", redacted)


if __name__ == "__main__":
    unittest.main()
