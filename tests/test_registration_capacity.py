import queue
import threading
import unittest
from unittest.mock import MagicMock, patch

import grok_register_ttk as reg
import register_cli


class RegistrationCapacityTests(unittest.TestCase):
    def setUp(self):
        register_cli._REGISTER_STOP.clear()
        register_cli._REGISTER_CAPACITY_STOP.clear()

    def tearDown(self):
        register_cli._REGISTER_STOP.clear()
        register_cli._REGISTER_CAPACITY_STOP.clear()

    def test_gui_capacity_exhaustion_stops_scheduling_without_counting_failure(self):
        gui = reg.GrokRegisterGUI.__new__(reg.GrokRegisterGUI)
        gui.stop_requested = False
        gui.mail_capacity_exhausted = False
        gui.is_running = True
        gui.fail_count = 0
        gui.stats_lock = threading.Lock()
        gui.log = MagicMock()
        gui.update_stats = MagicMock()
        gui._run_single_registration = MagicMock(
            side_effect=reg.CustomMailCapacityExhausted(total=2, consumed=2)
        )
        tasks = queue.Queue()
        tasks.put(1)
        tasks.put(2)

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": False}, clear=False),
            patch.object(reg, "start_browser"),
            patch.object(reg, "stop_browser"),
        ):
            gui._worker_loop(1, 2, tasks)

        self.assertTrue(gui.mail_capacity_exhausted)
        self.assertEqual(gui.fail_count, 0)
        self.assertEqual(gui._run_single_registration.call_count, 1)
        self.assertEqual(tasks.qsize(), 1)

    def test_cli_capacity_exhaustion_does_not_retry_or_consume_next_task(self):
        tasks = queue.Queue()
        tasks.put(1)
        tasks.put(2)
        exhausted = reg.CustomMailCapacityExhausted(total=2, consumed=2)

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": False}, clear=False),
            patch.object(register_cli, "_ensure_browser"),
            patch.object(reg, "open_signup_page") as open_signup,
            patch.object(reg, "fill_email_and_submit", side_effect=exhausted) as fill_email,
            patch.object(reg, "stop_browser"),
        ):
            register_cli._register_worker(
                1,
                tasks,
                2,
                "unused-accounts.txt",
                None,
                False,
                False,
            )

        self.assertTrue(register_cli._REGISTER_CAPACITY_STOP.is_set())
        self.assertEqual(open_signup.call_count, 1)
        self.assertEqual(fill_email.call_count, 1)
        self.assertEqual(tasks.qsize(), 1)


if __name__ == "__main__":
    unittest.main()
