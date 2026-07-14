import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import grok_register_ttk as reg


class Grok2ApiPoolDefaultTests(unittest.TestCase):
    def test_auto_add_defaults_are_disabled(self):
        self.assertFalse(reg.DEFAULT_CONFIG["grok2api_auto_add_local"])
        self.assertFalse(reg.DEFAULT_CONFIG["grok2api_auto_add_remote"])

    def test_missing_config_fields_do_not_write_any_pool(self):
        with (
            patch.object(reg, "config", {}),
            patch.object(reg, "add_token_to_grok2api_local_pool") as add_local,
            patch.object(reg, "add_token_to_grok2api_remote_pool") as add_remote,
        ):
            reg._add_token_to_grok2api_pools_sync("token", email="test@example.com")

        add_local.assert_not_called()
        add_remote.assert_not_called()

    def test_local_opt_in_only_writes_local_pool(self):
        with (
            patch.object(
                reg,
                "config",
                {"grok2api_auto_add_local": True, "grok2api_auto_add_remote": False},
            ),
            patch.object(reg, "add_token_to_grok2api_local_pool") as add_local,
            patch.object(reg, "add_token_to_grok2api_remote_pool") as add_remote,
        ):
            reg._add_token_to_grok2api_pools_sync("token", email="test@example.com")

        add_local.assert_called_once_with("token", email="test@example.com", log_callback=None)
        add_remote.assert_not_called()

    def test_remote_opt_in_only_writes_remote_pool(self):
        with (
            patch.object(
                reg,
                "config",
                {"grok2api_auto_add_local": False, "grok2api_auto_add_remote": True},
            ),
            patch.object(reg, "add_token_to_grok2api_local_pool") as add_local,
            patch.object(reg, "add_token_to_grok2api_remote_pool") as add_remote,
        ):
            reg._add_token_to_grok2api_pools_sync("token", email="test@example.com")

        add_local.assert_not_called()
        add_remote.assert_called_once_with("token", email="test@example.com", log_callback=None)

    def test_both_opt_ins_write_each_pool_once(self):
        with (
            patch.object(
                reg,
                "config",
                {"grok2api_auto_add_local": True, "grok2api_auto_add_remote": True},
            ),
            patch.object(reg, "add_token_to_grok2api_local_pool") as add_local,
            patch.object(reg, "add_token_to_grok2api_remote_pool") as add_remote,
        ):
            reg._add_token_to_grok2api_pools_sync("token", email="test@example.com")

        add_local.assert_called_once()
        add_remote.assert_called_once()

    def test_disabled_wrapper_does_not_submit_empty_async_job(self):
        logs = []
        with (
            patch.object(reg, "config", {}),
            patch.object(reg, "_get_side_effect_pool") as get_pool,
        ):
            result = reg.add_token_to_grok2api_pools(
                "token",
                email="test@example.com",
                log_callback=logs.append,
            )

        self.assertIsNone(result)
        get_pool.assert_not_called()
        self.assertEqual(logs, [])

    def test_load_config_uses_disabled_defaults_when_fields_are_missing(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "config.json"
            path.write_text(json.dumps({"email_provider": "custommail"}), encoding="utf-8")
            with (
                patch.object(reg, "CONFIG_FILE", str(path)),
                patch.object(reg, "config", reg.config.copy()),
            ):
                loaded = reg.load_config()

        self.assertFalse(loaded["grok2api_auto_add_local"])
        self.assertFalse(loaded["grok2api_auto_add_remote"])


if __name__ == "__main__":
    unittest.main()
