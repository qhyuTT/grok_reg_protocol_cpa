from __future__ import annotations

import json
import tempfile
import queue
import unittest
from pathlib import Path
from unittest.mock import patch

import cpa_xai
import cpa_xai.mint as mint_module
import cpa_export
import register_cli


class MintHealthGateTests(unittest.TestCase):
    def _mint_tokens(self) -> dict[str, object]:
        return {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
            "mint_method": "protocol",
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
                health_check=True,
                probe=False,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("rejected", result)
        self.assertEqual(result["health"]["classification"], "probe_error")
        self.assertFalse(result["health"]["reject_candidate"])
        self.assertEqual(result["path"], str(expected_path))
        writer.assert_called_once()


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

    def test_unknown_and_healthy_candidates_are_written_and_marked_used(self):
        for classification in ("unknown", "healthy"):
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as tempdir:
                accounts_path = Path(tempdir) / "accounts.txt"
                email = f"{classification}@example.com"
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
                        {"ok": True, "health": {"classification": classification}},
                        str(accounts_path),
                    )

                self.assertEqual(outcome, "accepted")
                self.assertEqual(
                    accounts_path.read_text(encoding="utf-8"),
                    f"{email}----secret----sso-cookie\n",
                )
                mark_error.assert_not_called()
                mark_used.assert_called_once_with(email, "secret")
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
