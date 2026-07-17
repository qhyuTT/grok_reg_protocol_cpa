import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.reactivate_cpa_auths import _atomic_install, _load_accounts, run


class ReactivateCpaAuthsTests(unittest.TestCase):
    @staticmethod
    def _fake_modules(export_result=None):
        reg = SimpleNamespace(config={}, stop_browser=mock.Mock(), _get_page=mock.Mock(return_value=None))
        cpa_export = SimpleNamespace(
            export_cpa_xai_for_account=mock.Mock(
                return_value=export_result
                or {"health": {"classification": "permission_denied", "http_status": 403}}
            )
        )
        return reg, cpa_export

    def test_load_accounts_deduplicates_and_preserves_first_row(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("one@example.com----pw1----sso1\n", encoding="utf-8")
            second.write_text(
                "one@example.com----pw2----sso2\ntwo@example.com----pw3----sso3\n",
                encoding="utf-8",
            )
            accounts, duplicates = _load_accounts([first, second])

        self.assertEqual([a.email for a in accounts], ["one@example.com", "two@example.com"])
        self.assertEqual(accounts[0].password, "pw1")
        self.assertEqual(duplicates, ["one@example.com"])

    def test_atomic_install_replaces_destination_and_keeps_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "nested" / "xai-one@example.com.json"
            source.write_text(json.dumps({"access_token": "new"}), encoding="utf-8")
            destination.parent.mkdir()
            destination.write_text(json.dumps({"access_token": "old"}), encoding="utf-8")

            _atomic_install(source, destination)

            self.assertEqual(json.loads(destination.read_text())["access_token"], "new")
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertFalse(destination.with_name(f".{destination.name}.reactivate.tmp").exists())

    def test_run_appends_activation_failure_once(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ledger = root / "accounts.txt"
            ledger.write_text("one@example.com----pw----sso\n", encoding="utf-8")
            live_dir = root / "live"
            live_dir.mkdir()
            (live_dir / "xai-one@example.com.json").write_text("{}", encoding="utf-8")
            reg, cpa_export = self._fake_modules()
            with mock.patch.dict(sys.modules, {"grok_register_ttk": reg, "cpa_export": cpa_export}), \
                mock.patch(
                    "scripts.reactivate_cpa_auths._load_config",
                    return_value={"registration_post_activation_settle_sec": 0},
                ), \
                mock.patch(
                    "scripts.reactivate_cpa_auths._activate_one",
                    return_value={"ok": False, "reason": "login_failed"},
                ), \
                mock.patch("builtins.print"):
                summary = run(
                    account_files=[ledger],
                    config_path=root / "config.json",
                    live_dir=live_dir,
                    sleep_sec=0,
                )
            self.assertEqual(len(summary["results"]), 1)
            self.assertEqual(summary["results"][0]["error"], "login_failed")
            cpa_export.export_cpa_xai_for_account.assert_not_called()

    def test_run_stops_only_on_exact_egress_access_denied(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ledger = root / "accounts.txt"
            ledger.write_text(
                "one@example.com----pw----sso\n"
                "two@example.com----pw----sso\n"
                "three@example.com----pw----sso\n",
                encoding="utf-8",
            )
            live_dir = root / "live"
            live_dir.mkdir()
            for email in ("one@example.com", "two@example.com", "three@example.com"):
                (live_dir / f"xai-{email}.json").write_text("{}", encoding="utf-8")
            reg, cpa_export = self._fake_modules()
            cpa_export.export_cpa_xai_for_account.side_effect = [
                {"health": {"classification": "forbidden_unknown", "http_status": 403}},
                {"health": {"classification": "forbidden_unknown", "http_status": 403}},
                {"health": {"classification": "forbidden_unknown", "http_status": 403}},
            ]
            activation = {"ok": True, "sso": "sso", "cookies": []}
            with mock.patch.dict(sys.modules, {"grok_register_ttk": reg, "cpa_export": cpa_export}), \
                mock.patch(
                    "scripts.reactivate_cpa_auths._load_config",
                    return_value={"registration_post_activation_settle_sec": 0},
                ), \
                mock.patch("scripts.reactivate_cpa_auths._activate_one", return_value=activation), \
                mock.patch("builtins.print"):
                summary = run(
                    account_files=[ledger],
                    config_path=root / "config.json",
                    live_dir=live_dir,
                    sleep_sec=0,
                )
            self.assertEqual(cpa_export.export_cpa_xai_for_account.call_count, 3)
            self.assertTrue(all("batch_stopped" not in row for row in summary["results"]))

            cpa_export.export_cpa_xai_for_account.reset_mock()
            cpa_export.export_cpa_xai_for_account.side_effect = [
                {"health": {"classification": "egress_access_denied", "http_status": 403}},
                {"health": {"classification": "egress_access_denied", "http_status": 403}},
                {"health": {"classification": "egress_access_denied", "http_status": 403}},
            ]
            with mock.patch.dict(sys.modules, {"grok_register_ttk": reg, "cpa_export": cpa_export}), \
                mock.patch(
                    "scripts.reactivate_cpa_auths._load_config",
                    return_value={"registration_post_activation_settle_sec": 0},
                ), \
                mock.patch("scripts.reactivate_cpa_auths._activate_one", return_value=activation), \
                mock.patch("builtins.print"):
                summary = run(
                    account_files=[ledger],
                    config_path=root / "config.json",
                    live_dir=live_dir,
                    sleep_sec=0,
                )
            self.assertEqual(cpa_export.export_cpa_xai_for_account.call_count, 2)
            self.assertEqual(summary["results"][-1]["batch_stopped"], "consecutive_egress_403")


if __name__ == "__main__":
    unittest.main()
