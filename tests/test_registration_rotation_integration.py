from __future__ import annotations

import json
import queue
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import grok_register_ttk as reg
import proxy_rotation
import register_cli


class FakeRotationManager:
    def __init__(self, leases, *, breaker=False):
        self.enabled = True
        self._leases = list(leases)
        self._breaker = breaker
        self.acquire_calls = 0
        self.releases = []

    def acquire(self, *, cancel=None):
        self.acquire_calls += 1
        value = self._leases.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def describe(self, lease):
        return {"lease_id": str(lease), "fixed": False}

    def release(self, lease, outcome):
        self.releases.append((lease, outcome))

    def should_stop_batch(self):
        return self._breaker


class CliRotationIntegrationTests(unittest.TestCase):
    def setUp(self):
        register_cli._REGISTER_STOP.clear()
        register_cli._REGISTER_CAPACITY_STOP.clear()
        register_cli._SCHEDULER_DONE.clear()

    def tearDown(self):
        register_cli._REGISTER_STOP.clear()
        register_cli._REGISTER_CAPACITY_STOP.clear()
        register_cli._SCHEDULER_DONE.clear()

    def test_failed_full_attempt_releases_and_reacquires_before_retry(self):
        tasks = queue.Queue()
        outcomes = queue.Queue()
        mint_queue = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        tasks.put(register_cli._TASK_STOP)
        manager = FakeRotationManager(["lease-1", "lease-2"])
        candidate = {
            "email": "healthy@example.com",
            "password": "secret",
            "sso": "sso-cookie",
            "cookies": [],
        }
        mint_result = {"ok": True, "health": {"classification": "healthy"}}

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": True}, clear=False),
            patch.object(proxy_rotation, "get_manager", return_value=manager),
            patch.object(register_cli, "register_one", side_effect=[None, candidate]) as register_one,
            patch.object(register_cli, "_run_mint_job", return_value=mint_result) as run_mint,
            patch.object(register_cli, "_safe_finalize_candidate", return_value="accepted"),
            patch.object(register_cli, "log"),
            patch.object(reg, "stop_browser") as stop_browser,
        ):
            register_cli._register_worker(
                worker_id=1,
                task_queue=tasks,
                total=1,
                accounts_file="unused.txt",
                mint_queue=mint_queue,
                forever=False,
                do_mint_inline=False,
                outcome_queue=outcomes,
            )

        self.assertEqual(register_one.call_count, 2)
        self.assertEqual(manager.acquire_calls, 2)
        self.assertEqual(manager.releases, [("lease-1", "reg_fail"), ("lease-2", "healthy")])
        self.assertTrue(mint_queue.empty(), "rotation must force inline mint even for direct callers")
        self.assertFalse(run_mint.call_args.args[2]["cpa_mint_browser_reuse"])
        self.assertGreaterEqual(stop_browser.call_count, 2)
        self.assertEqual(outcomes.get_nowait()["status"], "accepted")

    def test_async_mint_emits_only_worker_terminal_outcome(self):
        tasks = queue.Queue()
        outcomes = queue.Queue()
        mint_queue = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        tasks.put(register_cli._TASK_STOP)
        candidate = {
            "email": "denied@example.com",
            "password": "secret",
            "sso": "sso-cookie",
            "cookies": [],
        }

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": False}, clear=False),
            patch.object(register_cli, "register_one", return_value=candidate),
            patch.object(register_cli, "log"),
            patch.object(reg, "stop_browser"),
        ):
            register_cli._register_worker(
                worker_id=1,
                task_queue=tasks,
                total=1,
                accounts_file="unused.txt",
                mint_queue=mint_queue,
                forever=False,
                do_mint_inline=False,
                outcome_queue=outcomes,
            )

        self.assertTrue(outcomes.empty(), "register worker must defer the terminal outcome")
        self.assertEqual(mint_queue.qsize(), 1)
        mint_queue.put(register_cli._MINT_STOP)
        with (
            patch.object(register_cli, "_run_mint_job", return_value={"ok": False}),
            patch.object(register_cli, "_safe_finalize_candidate", return_value="rejected"),
            patch.object(register_cli, "log"),
        ):
            register_cli._mint_worker("M1", mint_queue, {})

        self.assertEqual(outcomes.get_nowait()["status"], "rejected")
        self.assertTrue(outcomes.empty())

    def test_egress_unavailable_stops_without_starting_registration(self):
        tasks = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        manager = FakeRotationManager(
            [proxy_rotation.EgressUnavailable("all eligible egresses cooling")]
        )

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": True}, clear=False),
            patch.object(proxy_rotation, "get_manager", return_value=manager),
            patch.object(register_cli, "register_one") as register_one,
            patch.object(register_cli, "log") as log,
            patch.object(reg, "stop_browser"),
        ):
            register_cli._register_worker(1, tasks, 1, "unused.txt", None, False, True)

        self.assertTrue(register_cli._REGISTER_STOP.is_set())
        register_one.assert_not_called()
        self.assertTrue(any("批次停止" in call.args[1] for call in log.call_args_list))

    def test_startup_validation_failure_is_not_downgraded(self):
        with (
            patch.object(
                proxy_rotation,
                "validate_rotation_config",
                side_effect=proxy_rotation.EgressUnavailable("proxy mismatch"),
            ),
            patch.object(proxy_rotation, "get_manager") as get_manager,
        ):
            with self.assertRaises(proxy_rotation.EgressUnavailable):
                register_cli._prepare_rotation_manager({"proxy_rotation_enabled": True})

        get_manager.assert_not_called()

    def test_gui_and_example_use_general_us_node_defaults(self):
        example = json.loads(
            (Path(__file__).resolve().parents[1] / "config.example.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(reg.DEFAULT_CONFIG["proxy_rotation_node_filter"], "(?i)美国")
        self.assertEqual(
            reg.DEFAULT_CONFIG["proxy_rotation_node_filter"],
            example["proxy_rotation_node_filter"],
        )
        self.assertEqual(
            reg.DEFAULT_CONFIG["proxy_rotation_node_exclude"],
            example["proxy_rotation_node_exclude"],
        )


class GuiRotationIntegrationTests(unittest.TestCase):
    def _gui(self):
        gui = reg.GrokRegisterGUI.__new__(reg.GrokRegisterGUI)
        gui.stop_requested = False
        gui.mail_capacity_exhausted = False
        gui.egress_batch_stopped = False
        gui.is_running = True
        gui.fail_count = 0
        gui.stats_lock = threading.Lock()
        gui.log = MagicMock()
        gui.update_stats = MagicMock()
        gui._trace_call = MagicMock()
        gui.behavior_trace = None
        gui.next_attempt_idx = 2
        return gui

    def test_confirmed_healthy_result_is_released_as_healthy(self):
        gui = self._gui()
        gui._run_single_registration = MagicMock(
            return_value={"cpa": {"ok": True, "health": {"classification": "healthy"}}}
        )
        tasks = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        manager = FakeRotationManager(["lease-healthy"])

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": True}, clear=False),
            patch.object(proxy_rotation, "get_manager", return_value=manager),
            patch.object(reg, "start_browser"),
            patch.object(reg, "stop_browser"),
        ):
            gui._worker_loop(1, 1, tasks)

        self.assertEqual(manager.releases, [("lease-healthy", "healthy")])
        self.assertFalse(gui.egress_batch_stopped)

    def test_browser_closes_before_rotation_lease_release(self):
        gui = self._gui()
        gui._run_single_registration = MagicMock(side_effect=RuntimeError("boom"))
        tasks = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        manager = FakeRotationManager(["lease-failed"])
        events = []

        def stop_browser():
            events.append("browser_closed")

        def release(lease, outcome):
            events.append(f"release:{lease}:{outcome}")
            manager.releases.append((lease, outcome))

        manager.release = release
        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": True}, clear=False),
            patch.object(proxy_rotation, "get_manager", return_value=manager),
            patch.object(reg, "start_browser"),
            patch.object(reg, "stop_browser", side_effect=stop_browser),
            patch("cpa_xai.browser_confirm.shutdown_mint_browsers"),
        ):
            gui._worker_loop(1, 1, tasks)

        release_index = next(i for i, event in enumerate(events) if event.startswith("release:"))
        self.assertIn("browser_closed", events[:release_index])

    def test_egress_breaker_stops_without_enqueuing_replacement(self):
        gui = self._gui()
        rejection = reg.PermissionDeniedRegistration("denied@example.com")
        rejection.mint_result = {
            "ok": False,
            "rejected": True,
            "health": {"classification": "egress_access_denied"},
        }
        gui._run_single_registration = MagicMock(side_effect=rejection)
        tasks = queue.Queue()
        tasks.put({"idx": 1, "slot": 1, "replacement": 0})
        tasks.put({"idx": 2, "slot": 2, "replacement": 0})
        manager = FakeRotationManager(["lease-denied"], breaker=True)

        with (
            patch.dict(
                reg.config,
                {
                    "proxy_rotation_enabled": True,
                    "registration_health_max_replacements_per_slot": 3,
                },
                clear=False,
            ),
            patch.object(proxy_rotation, "get_manager", return_value=manager),
            patch.object(reg, "start_browser"),
            patch.object(reg, "stop_browser"),
        ):
            gui._worker_loop(1, 2, tasks)

        self.assertEqual(manager.releases, [("lease-denied", "egress_access_denied")])
        self.assertTrue(gui.egress_batch_stopped)
        self.assertEqual(gui._run_single_registration.call_count, 1)
        self.assertEqual(tasks.qsize(), 1, "existing work remains undispatched and no replacement is added")
        self.assertTrue(
            any("批次熔断" in call.args[0] for call in gui.log.call_args_list)
        )


if __name__ == "__main__":
    unittest.main()
