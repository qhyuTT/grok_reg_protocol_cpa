import sys
import os
import queue
import threading
import tempfile
import types
import unittest
from unittest.mock import MagicMock, PropertyMock, call, patch

import browser_lifecycle
import grok_register_ttk as reg
import register_cli
import tab_pool
from cpa_xai import browser_confirm
from cpa_xai import mint as mint_module


class _FakeChromiumOptions:
    def auto_port(self):
        return self

    def set_timeouts(self, **_kwargs):
        return self

    def set_argument(self, _argument):
        return self

    def add_extension(self, _path):
        return self

    def headless(self, _enabled):
        return self

    def set_browser_path(self, _path):
        return self


class BrowserLifecycleTests(unittest.TestCase):
    def setUp(self):
        tab_pool.TabPool._options_factory = None
        tab_pool.TabPool._thread_local = threading.local()
        tab_pool.TabPool._all_browsers = []
        tab_pool.TabPool._accept_new = True
        tab_pool.TabPool._permanent_block = False
        tab_pool.TabPool._failed_closes = set()

    def tearDown(self):
        # Reset state directly so a failed lifecycle assertion cannot invoke a
        # real or partially mocked browser cleanup path during test teardown.
        tab_pool.TabPool._options_factory = None
        tab_pool.TabPool._thread_local = threading.local()
        tab_pool.TabPool._all_browsers = []
        tab_pool.TabPool._accept_new = True
        tab_pool.TabPool._permanent_block = False
        tab_pool.TabPool._failed_closes = set()

    def test_tab_pool_closes_browser_when_initial_tab_lookup_fails(self):
        browser = MagicMock(name="browser")
        type(browser).tab_ids = PropertyMock(side_effect=RuntimeError("tab lookup failed"))
        drission_page = types.SimpleNamespace(Chromium=MagicMock(return_value=browser))
        tab_pool.TabPool.init(lambda: object())

        with (
            patch.dict(sys.modules, {"DrissionPage": drission_page}),
            patch.object(tab_pool, "close_owned_browser", return_value=True) as close_browser,
        ):
            with self.assertRaisesRegex(RuntimeError, "tab lookup failed"):
                tab_pool.TabPool.get_tab()

        close_browser.assert_called_once_with(browser)
        self.assertEqual(tab_pool.TabPool.live_count(), 0)
        self.assertIsNone(tab_pool.TabPool.get_browser())

    def test_tab_pool_reaps_process_when_chromium_constructor_fails(self):
        options = MagicMock(name="options")
        drission_page = types.SimpleNamespace(
            Chromium=MagicMock(side_effect=RuntimeError("connect failed"))
        )
        tab_pool.TabPool.init(lambda: options)

        with (
            patch.dict(sys.modules, {"DrissionPage": drission_page}),
            patch.object(tab_pool, "cleanup_failed_browser_start") as cleanup,
        ):
            with self.assertRaisesRegex(RuntimeError, "connect failed"):
                tab_pool.TabPool.get_tab()

        cleanup.assert_called_once_with(options)
        self.assertEqual(tab_pool.TabPool.live_count(), 0)

    def test_release_tab_uses_unified_browser_exit(self):
        browser = MagicMock(name="browser")
        tab_pool.TabPool._thread_local.browser = browser
        tab_pool.TabPool._thread_local.tab = MagicMock(name="tab")
        tab_pool.TabPool._thread_local.served = 3
        tab_pool.TabPool._all_browsers = [browser]

        with patch.object(tab_pool, "close_owned_browser", return_value=True) as close_browser:
            tab_pool.TabPool.release_tab()

        close_browser.assert_called_once_with(browser)
        self.assertEqual(tab_pool.TabPool.live_count(), 0)
        self.assertIsNone(tab_pool.TabPool.get_browser())
        self.assertEqual(tab_pool.TabPool.served_count(), 0)

    def test_shutdown_uses_unified_browser_exit_for_every_tracked_browser(self):
        current = MagicMock(name="current_browser")
        other = MagicMock(name="other_browser")
        tab_pool.TabPool._thread_local.browser = current
        tab_pool.TabPool._thread_local.tab = MagicMock(name="tab")
        tab_pool.TabPool._all_browsers = [current, other]

        with patch.object(tab_pool, "close_owned_browser", return_value=True) as close_browser:
            tab_pool.TabPool.shutdown()

        self.assertEqual(close_browser.call_args_list, [call(current), call(other)])
        self.assertEqual(tab_pool.TabPool.live_count(), 0)
        self.assertIsNone(tab_pool.TabPool.get_browser())

    def test_permanent_shutdown_blocks_late_browser_creation(self):
        tab_pool.TabPool.init(lambda: object())
        tab_pool.TabPool.shutdown(block_new=True)

        with self.assertRaisesRegex(RuntimeError, "disabled during shutdown"):
            tab_pool.TabPool.get_tab()

    def test_failed_close_prevents_creating_another_browser(self):
        browser = MagicMock(name="stuck_browser")
        tab_pool.TabPool._thread_local.browser = browser
        tab_pool.TabPool._thread_local.tab = None
        tab_pool.TabPool._all_browsers = [browser]

        with patch.object(tab_pool, "close_owned_browser", return_value=False) as close_browser:
            with self.assertRaisesRegex(RuntimeError, "refusing to create another"):
                tab_pool.TabPool.get_tab()

        close_browser.assert_called_once_with(browser)
        self.assertIs(tab_pool.TabPool.get_browser(), browser)
        self.assertEqual(tab_pool.TabPool.live_count(), 1)

    def test_successful_retry_after_failed_close_reenables_creation(self):
        browser = MagicMock(name="stuck_then_closed")
        tab_pool.TabPool._thread_local.browser = browser
        tab_pool.TabPool._thread_local.tab = None
        tab_pool.TabPool._all_browsers = [browser]

        with patch.object(tab_pool, "close_owned_browser", side_effect=[False, True]):
            self.assertFalse(tab_pool.TabPool.release_tab())
            self.assertTrue(tab_pool.TabPool.release_tab())

        self.assertTrue(tab_pool.TabPool._accept_new)
        self.assertEqual(tab_pool.TabPool.live_count(), 0)

    def test_cpa_standalone_browser_closes_when_latest_tab_lookup_fails(self):
        browser = MagicMock(name="cpa_browser")
        type(browser).latest_tab = PropertyMock(side_effect=RuntimeError("latest tab failed"))
        drission_page = types.SimpleNamespace(
            Chromium=MagicMock(return_value=browser),
            ChromiumOptions=_FakeChromiumOptions,
        )

        with (
            patch.dict(sys.modules, {"DrissionPage": drission_page}),
            patch.object(browser_confirm.Path, "is_file", return_value=False),
            patch.object(browser_confirm.os.path, "isfile", return_value=False),
            patch.object(
                browser_confirm, "close_owned_browser", return_value=True
            ) as close_browser,
        ):
            with self.assertRaisesRegex(RuntimeError, "latest tab failed"):
                browser_confirm.create_standalone_page()

        close_browser.assert_called_once_with(browser)


class ReliableCloseTests(unittest.TestCase):
    def test_close_waits_for_graceful_process_exit(self):
        browser = MagicMock(process_id=4321, address="127.0.0.1:9222")
        process = MagicMock()
        process.create_time.return_value = 123.0
        process.wait.return_value = 0

        with patch.object(browser_lifecycle.psutil, "Process", return_value=process):
            closed = browser_lifecycle.close_owned_browser(browser, timeout=1)

        self.assertTrue(closed)
        browser.quit.assert_called_once_with(timeout=1, force=True, del_data=True)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_close_terminates_then_kills_a_stuck_process(self):
        browser = MagicMock(
            process_id=4321,
            address="127.0.0.1:9222",
            user_data_path="/tmp/DrissionPage/autoPortData/9222",
        )
        browser.quit.side_effect = RuntimeError("cdp disconnected")
        process = MagicMock()
        process.create_time.return_value = 123.0
        process.is_running.return_value = True
        process.status.return_value = "running"
        process.ppid.return_value = os.getpid()
        process.cmdline.return_value = [
            "Google Chrome",
            "--remote-debugging-port=9222",
            "--user-data-dir=/tmp/DrissionPage/autoPortData/9222",
        ]
        process.wait.side_effect = [
            browser_lifecycle.psutil.TimeoutExpired(4321),
            browser_lifecycle.psutil.TimeoutExpired(4321),
            0,
        ]

        with patch.object(browser_lifecycle.psutil, "Process", return_value=process):
            closed = browser_lifecycle.close_owned_browser(browser, timeout=1)

        self.assertTrue(closed)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()

    def test_close_refuses_to_signal_an_unowned_pid(self):
        browser = MagicMock(process_id=4321, address="127.0.0.1:9222")
        process = MagicMock()
        process.create_time.return_value = 123.0
        process.is_running.return_value = True
        process.status.return_value = "running"
        process.ppid.return_value = 1
        process.cmdline.return_value = ["Google Chrome", "--remote-debugging-port=9222"]
        process.wait.side_effect = browser_lifecycle.psutil.TimeoutExpired(4321)

        with patch.object(browser_lifecycle.psutil, "Process", return_value=process):
            closed = browser_lifecycle.close_owned_browser(browser, timeout=1)

        self.assertFalse(closed)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_failed_start_cleanup_uses_exact_argument_matching(self):
        options = MagicMock(
            address="127.0.0.1:9222",
            user_data_path="/tmp/DrissionPage/autoPortData/9222",
        )
        exact = MagicMock(pid=100)
        exact.cmdline.return_value = [
            "Google Chrome",
            "--remote-debugging-port=9222",
            "--user-data-dir=/tmp/DrissionPage/autoPortData/9222",
        ]
        prefix_only = MagicMock(pid=101)
        prefix_only.cmdline.return_value = [
            "Google Chrome",
            "--remote-debugging-port=92220",
            "--user-data-dir=/tmp/DrissionPage/autoPortData/92220",
        ]
        parent = MagicMock()
        parent.children.return_value = [prefix_only, exact]

        with (
            patch.object(browser_lifecycle.psutil, "Process", return_value=parent),
            patch.object(
                browser_lifecycle.psutil,
                "wait_procs",
                return_value=([exact], []),
            ),
        ):
            cleaned = browser_lifecycle.cleanup_failed_browser_start(options)

        self.assertEqual(cleaned, 1)
        exact.terminate.assert_called_once_with()
        prefix_only.terminate.assert_not_called()

    def test_close_without_pid_reports_quit_failure(self):
        browser = MagicMock(process_id=None, address="remote:9222")
        browser.quit.side_effect = RuntimeError("quit failed")

        self.assertFalse(browser_lifecycle.close_owned_browser(browser, timeout=1))


class BrowserDefaultTests(unittest.TestCase):
    def tearDown(self):
        register_cli._REGISTER_STOP.clear()

    def test_registration_browser_reuse_is_opt_in(self):
        args = register_cli.build_parser().parse_args([])

        self.assertFalse(reg.PERF_FLAGS["browser_reuse"])
        self.assertFalse(args.browser_reuse)
        self.assertFalse(args.no_browser_reuse)

    def test_cli_accepts_explicit_browser_reuse(self):
        args = register_cli.build_parser().parse_args(["--browser-reuse"])

        self.assertTrue(args.browser_reuse)
        self.assertFalse(args.no_browser_reuse)

    def test_cli_cancel_callback_tracks_global_stop_event(self):
        cancel = register_cli.DummyStop()
        self.assertFalse(cancel())

        register_cli._REGISTER_STOP.set()

        self.assertTrue(cancel())

    def test_prepare_without_reuse_closes_without_eager_restart(self):
        with (
            patch.object(reg, "PERF_FLAGS", {**reg.PERF_FLAGS, "browser_reuse": False}),
            patch.object(reg.TabPool, "served_count", return_value=0),
            patch.object(reg.TabPool, "release_tab") as release_tab,
            patch.object(reg, "start_browser") as start_browser,
        ):
            result = reg.prepare_browser_for_next_account()

        self.assertEqual(result, (None, None))
        release_tab.assert_called_once_with()
        start_browser.assert_not_called()

    def test_gui_worker_closes_account_without_preopening_next_browser(self):
        gui = reg.GrokRegisterGUI.__new__(reg.GrokRegisterGUI)
        gui.stop_requested = False
        gui.is_running = True
        gui.fail_count = 0
        gui.stats_lock = threading.Lock()
        gui.log = MagicMock()
        gui.update_stats = MagicMock()
        gui._run_single_registration = MagicMock()
        task_queue = queue.Queue()
        task_queue.put(1)

        with (
            patch.dict(reg.config, {"proxy_rotation_enabled": False}, clear=False),
            patch.object(reg, "start_browser") as start_browser,
            patch.object(reg, "stop_browser") as stop_browser,
            patch.object(reg, "restart_browser") as restart_browser,
            patch.object(reg, "sleep_with_cancel") as sleep_with_cancel,
        ):
            gui._worker_loop(1, 1, task_queue)

        start_browser.assert_called_once()
        self.assertGreaterEqual(stop_browser.call_count, 1)
        restart_browser.assert_not_called()
        sleep_with_cancel.assert_not_called()

    def test_cancelled_protocol_mint_does_not_open_fallback_browser(self):
        with tempfile.TemporaryDirectory() as auth_dir:
            with (
                patch.object(
                    mint_module,
                    "mint_with_sso_protocol",
                    side_effect=mint_module.ProtocolMintError("cancelled"),
                ) as protocol_mint,
                patch.object(mint_module, "mint_with_browser") as browser_mint,
            ):
                result = mint_module.mint_and_export(
                    email="test@example.com",
                    password="password",
                    auth_dir=auth_dir,
                    sso="sso-cookie",
                    prefer_auth_code=False,
                    skip_device_when_referrer_required=False,
                    probe=False,
                    cancel=lambda: True,
                )

        self.assertEqual(result["error"], "cancelled")
        protocol_mint.assert_called_once()
        browser_mint.assert_not_called()


if __name__ == "__main__":
    unittest.main()
