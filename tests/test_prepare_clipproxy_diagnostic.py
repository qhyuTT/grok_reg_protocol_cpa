import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.prepare_clipproxy_diagnostic import prepare


class PrepareCliProxyDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.project_config = self.root / "config.json"
        self.project_config.write_text(
            json.dumps(
                {
                    "proxy": "http://127.0.0.1:7890",
                    "cpa_proxy": "http://127.0.0.1:7890",
                }
            ),
            encoding="utf-8",
        )

    def make_auth(self, *, disabled=False, expiry=None):
        path = self.root / "xai-test@example.com.json"
        path.write_text(
            json.dumps(
                {
                    "type": "xai",
                    "email": "test@example.com",
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "disabled": disabled,
                    "expired": expiry
                    or (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_prepare_uses_cpa_proxy_and_safe_retry_limits(self):
        output = self.root / "diagnostic"
        result = prepare(
            project_config=self.project_config,
            output_dir=output,
            port=18317,
            source_auth=self.make_auth(),
        )

        config_text = Path(result["config_path"]).read_text(encoding="utf-8")
        self.assertIn('host: "127.0.0.1"', config_text)
        self.assertIn("port: 18317", config_text)
        self.assertIn('proxy-url: "http://127.0.0.1:7890"', config_text)
        self.assertEqual(config_text.count("request-retry: 0"), 1)
        self.assertEqual(config_text.count("max-retry-credentials: 1"), 1)
        self.assertEqual(config_text.count("max-retry-interval: 0"), 1)
        self.assertEqual(len(list(Path(result["auth_dir"]).glob("*.json"))), 1)
        self.assertTrue(Path(result["key_path"]).read_text(encoding="utf-8").startswith("diag-"))

        if os.name == "posix":
            self.assertEqual(Path(result["config_path"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(result["key_path"]).stat().st_mode & 0o777, 0o600)

    def test_prepare_rejects_disabled_auth(self):
        with self.assertRaisesRegex(SystemExit, "disabled"):
            prepare(
                project_config=self.project_config,
                output_dir=self.root / "diagnostic",
                port=18317,
                source_auth=self.make_auth(disabled=True),
            )

    def test_prepare_without_source_clears_previous_diagnostic_auth(self):
        output = self.root / "diagnostic"
        prepare(
            project_config=self.project_config,
            output_dir=output,
            port=18317,
            source_auth=self.make_auth(),
        )
        self.assertEqual(len(list((output / "auth").glob("*.json"))), 1)

        result = prepare(
            project_config=self.project_config,
            output_dir=output,
            port=18317,
            source_auth=None,
        )

        self.assertEqual(len(list(Path(result["auth_dir"]).glob("*.json"))), 0)

    def test_prepare_rejects_expired_auth(self):
        expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.assertRaisesRegex(SystemExit, "expired"):
            prepare(
                project_config=self.project_config,
                output_dir=self.root / "diagnostic",
                port=18317,
                source_auth=self.make_auth(expiry=expired),
            )

    def test_prepare_rejects_mismatched_registration_and_cpa_proxy(self):
        self.project_config.write_text(
            json.dumps(
                {
                    "proxy": "http://127.0.0.1:7890",
                    "cpa_proxy": "http://127.0.0.1:7891",
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(SystemExit, "same registration/CPA egress"):
            prepare(
                project_config=self.project_config,
                output_dir=self.root / "diagnostic",
                port=18317,
                source_auth=self.make_auth(),
            )


if __name__ == "__main__":
    unittest.main()
