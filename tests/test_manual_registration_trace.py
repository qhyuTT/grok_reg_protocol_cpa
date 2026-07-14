import json
import os
import stat
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import manual_registration_trace as trace


def _iso(second: int) -> str:
    return datetime(2026, 7, 14, 1, 2, second, tzinfo=timezone.utc).isoformat()


class RedactionTests(unittest.TestCase):
    def test_recursive_redaction_removes_headers_bodies_inputs_and_free_text(self):
        raw = {
            "headers": {
                "Authorization": "Bearer top-secret-token",
                "Cookie": "sso=secret-cookie; theme=dark",
                "X-Contact": "person@example.com",
            },
            "postData": '{"password":"hunter2","email":"person@example.com"}',
            "target": {"value": "hunter2", "text": "person@example.com"},
            "message": "token=abc123456789 and person@example.com",
        }

        safe = trace.redact_sensitive(raw)
        serialized = json.dumps(safe)

        self.assertNotIn("top-secret-token", serialized)
        self.assertNotIn("secret-cookie", serialized)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("person@example.com", serialized)
        self.assertEqual(safe["headers"]["Authorization"], "<redacted:sensitive>")
        self.assertEqual(safe["postData"], "<redacted:body>")
        self.assertEqual(safe["target"]["value"], "<redacted:input>")

    def test_url_redaction_preserves_endpoint_but_not_values(self):
        safe = trace.redact_url(
            "https://accounts.x.ai/callback/abcdefghijklmnopqrstuvwxyz1234567890?code=abc123&email=a%40b.com#token"
        )

        self.assertTrue(safe.startswith("https://accounts.x.ai/callback/"))
        self.assertIn("code=", safe)
        self.assertNotIn("abc123", safe)
        self.assertNotIn("a%40b.com", safe)
        self.assertNotIn("#token", safe)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz1234567890", safe)

    def test_url_redaction_covers_encoded_email_codes_and_userinfo(self):
        samples = (
            "https://user:pass@accounts.x.ai/u/person%40example.com",
            "https://accounts.x.ai/verify/ABC-123",
            "https://accounts.x.ai/callback/shortSecretToken12345",
        )
        serialized = "\n".join(trace.redact_url(item) for item in samples)
        self.assertNotIn("user:pass", serialized)
        self.assertNotIn("person@example.com", serialized)
        self.assertNotIn("ABC-123", serialized)
        self.assertNotIn("shortSecretToken12345", serialized)

    def test_free_text_redacts_verification_codes(self):
        self.assertNotIn("123456", trace.redact_text("aria-label=123456"))


class StableSelectorTests(unittest.TestCase):
    def test_selector_priority_prefers_testid_then_name(self):
        target = {
            "tag": "button",
            "id": "stable-id",
            "attributes": {"data-testid": "continue", "name": "submit", "role": "button"},
        }
        self.assertEqual(trace.stable_selector(target), '[data-testid="continue"]')

        target["attributes"].pop("data-testid")
        self.assertEqual(trace.stable_selector(target), 'button[name="submit"]')

    def test_dynamic_id_is_skipped_for_stable_attribute(self):
        target = {
            "tag": "input",
            "id": "radix-239482734",
            "attributes": {"id": "radix-239482734", "placeholder": "Verification code"},
            "cssPath": "main > input:nth-of-type(2)",
        }

        self.assertEqual(
            trace.stable_selector(target),
            'input[placeholder="Verification code"]',
        )


class TraceSummaryTests(unittest.TestCase):
    def test_summary_correlates_requests_responses_and_user_steps(self):
        events = [
            {
                "recorded_at": _iso(1),
                "category": "user",
                "payload": {
                    "type": "input",
                    "url": "https://accounts.x.ai/sign-up?email=person@example.com",
                    "target": {
                        "tag": "input",
                        "attributes": {"name": "email"},
                        "value": "person@example.com",
                    },
                },
            },
            {
                "recorded_at": _iso(2),
                "category": "user",
                "payload": {"type": "click", "target": {"tag": "button", "attributes": {"data-testid": "next"}}},
            },
            {
                "recorded_at": _iso(3),
                "category": "user",
                "payload": {"type": "pointermove", "target": {"tag": "body"}},
            },
        ]
        network = [
            {
                "recorded_at": _iso(4),
                "category": "request",
                "payload": {
                    "requestId": "1",
                    "timestamp": 10.0,
                    "request": {
                        "method": "POST",
                        "url": "https://accounts.x.ai/api/register?token=raw-secret",
                        "postData": "password=hunter2",
                    },
                },
            },
            {
                "recorded_at": _iso(5),
                "category": "response",
                "payload": {
                    "requestId": "1",
                    "timestamp": 10.25,
                    "response": {"status": 200, "url": "https://accounts.x.ai/api/register"},
                },
            },
        ]

        summary = trace.summarize_trace(events, network)
        serialized = json.dumps(summary)

        self.assertEqual(summary["user_event_count"], 3)
        self.assertEqual(summary["network_request_count"], 1)
        self.assertEqual(summary["network_response_count"], 1)
        self.assertEqual(summary["response_statuses"], {"200": 1})
        self.assertEqual(summary["endpoints"][0]["average_duration_ms"], 250.0)
        self.assertIn('input[name="email"]', [item["selector"] for item in summary["selectors"]])
        self.assertFalse(any(item["action"] == "pointermove" for item in summary["timeline"]))
        self.assertNotIn("raw-secret", serialized)
        self.assertNotIn("person@example.com", serialized)
        self.assertNotIn("hunter2", serialized)


class SecureArtifactTests(unittest.TestCase):
    def test_finalize_writes_private_reports_and_deletes_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary) / "session"
            session.mkdir(mode=0o700)
            writer = trace.RawTraceWriter(session / "raw")
            writer.event(
                "user",
                "tab-1",
                {
                    "type": "input",
                    "url": "https://accounts.x.ai/sign-up?email=person@example.com",
                    "target": {
                        "tag": "input",
                        "attributes": {"name": "email"},
                        "value": "person@example.com",
                    },
                },
            )
            writer.network(
                "request",
                "tab-1",
                {
                    "requestId": "1",
                    "request": {
                        "method": "POST",
                        "url": "https://accounts.x.ai/api/register?token=secret",
                        "headers": {"Cookie": "sso=secret"},
                        "postData": "password=hunter2",
                    },
                },
            )
            raw_files = list((session / "raw").glob("*.jsonl"))
            writer.close()

            for path in raw_files:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((session / "raw").stat().st_mode), 0o700)

            report_path, timeline_path = trace.finalize_trace(session)

            self.assertFalse((session / "raw").exists())
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(timeline_path.stat().st_mode), 0o600)
            combined = report_path.read_text() + timeline_path.read_text()
            for secret in ("person@example.com", "hunter2", "sso=secret", "token=secret"):
                self.assertNotIn(secret, combined)

    def test_report_failure_preserves_raw_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary) / "session"
            session.mkdir(mode=0o700)
            writer = trace.RawTraceWriter(session / "raw")
            writer.event("user", "tab-1", {"type": "click"})
            writer.close()

            with patch.object(trace, "render_report", side_effect=RuntimeError("report failed")):
                with self.assertRaisesRegex(RuntimeError, "report failed"):
                    trace.finalize_trace(session)

            self.assertTrue((session / "raw" / "events.jsonl").is_file())


class BrowserOptionsTests(unittest.TestCase):
    def test_project_options_are_reused_with_headed_private_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = MagicMock()
            chromium_options = MagicMock(return_value=options)
            fake_reg = types.SimpleNamespace(
                config={"proxy": "http://127.0.0.1:7890"},
            )

            with (
                patch.dict(sys.modules, {"grok_register_ttk": fake_reg}),
                patch("DrissionPage.ChromiumOptions", chromium_options),
            ):
                result = trace.build_browser_options(Path(temporary) / "raw")

            self.assertIs(result, options)
            chromium_options.assert_called_once_with(read_file=False)
            options.headless.assert_called_once_with(False)
            options.auto_port.assert_called_once_with()
            options.set_proxy.assert_called_once_with("http://127.0.0.1:7890")
            called_args = [call.args[0] for call in options.set_argument.call_args_list]
            self.assertNotIn("--user-agent", called_args)
            self.assertNotIn("--no-sandbox", called_args)
            profile_root = Path(options.set_tmp_path.call_args.args[0])
            self.assertEqual(profile_root.name, "DrissionPage")
            self.assertEqual(stat.S_IMODE(profile_root.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
