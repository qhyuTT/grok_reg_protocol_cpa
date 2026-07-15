from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import automatic_registration_trace as trace
import grok_register_ttk as reg
from tab_pool import TabPool


class _Driver:
    def __init__(self):
        self.callbacks = {}

    def set_callback(self, event, callback, immediate=False):
        self.callbacks[event] = callback


class _Tab:
    tab_id = "shared-tab-id"

    def __init__(self):
        self.driver = _Driver()
        self.init_scripts = []

    def add_init_js(self, script):
        self.init_scripts.append(script)

    def run_cdp(self, method, **_kwargs):
        if method == "Runtime.evaluate" and "document.body" in str(_kwargs.get("expression") or ""):
            return {
                "result": {
                    "value": {
                        "url": "https://accounts.x.ai/sign-up?email=person@example.com",
                        "title": "Verify 123456",
                        "readyState": "complete",
                        "headings": ["person@example.com"],
                        "dialogs": [],
                        "controls": [
                            {
                                "tag": "input",
                                "name": "password",
                                "text": "hunter2",
                            }
                        ],
                        "visibleText": "person@example.com code 123456 token=top-secret-token",
                    }
                }
            }
        return {}


class _Browser:
    def __init__(self, tab):
        self.tab = tab
        self.tab_ids = [tab.tab_id]

    def get_tab(self, _tab_id):
        return self.tab


class AutomaticTraceRedactionTests(unittest.TestCase):
    def test_page_and_dom_events_are_redacted_before_persistence(self):
        with tempfile.TemporaryDirectory() as temporary:
            batch = trace.AutomaticRegistrationTraceBatch(temporary, page_state_interval=60)
            attempt = batch.begin_attempt(worker_id=1, idx=1, slot=1, replacement=0)
            tab = _Tab()
            browser = _Browser(tab)
            attempt.attach_browser(browser, tab)

            tab.driver.callbacks["Runtime.bindingCalled"](
                name=trace.JS_BINDING_NAME,
                payload=json.dumps(
                    {
                        "type": "input",
                        "url": "https://accounts.x.ai/sign-up?email=person@example.com",
                        "target": {
                            "tag": "input",
                            "name": "password",
                            "value": "hunter2",
                            "text": "hunter2",
                            "outerHTML": '<input name="password" value="hunter2">',
                        },
                    }
                ),
            )
            batch.bind_identity("person@example.com")
            batch.finish_attempt("accepted")
            batch.finalize()

            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in Path(temporary).rglob("*")
                if path.is_file()
            )
            for secret in (
                "person@example.com",
                "hunter2",
                "123456",
                "top-secret-token",
                '<input name="password" value="hunter2">',
            ):
                self.assertNotIn(secret, combined)
            self.assertIn("<redacted", combined)

    def test_batch_report_links_success_and_permission_denied_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            batch = trace.AutomaticRegistrationTraceBatch(temporary, page_state_interval=60)

            batch.begin_attempt(worker_id=1, idx=1, slot=1, replacement=0)
            batch.bind_identity("success@example.com")
            batch.record_health(
                {
                    "health": {
                        "classification": "healthy",
                        "confidence": "confirmed",
                        "attempts": [
                            {
                                "attempt": 1,
                                "offset_sec": 15,
                                "classification": "healthy",
                                "http_status": 200,
                            }
                        ],
                    }
                }
            )
            batch.finish_attempt("accepted")

            batch.begin_attempt(worker_id=1, idx=2, slot=2, replacement=0)
            batch.bind_identity("denied@example.com")
            batch.record_health(
                {
                    "health": {
                        "classification": "permission_denied",
                        "confidence": "confirmed",
                        "reject_candidate": True,
                        "reject_reason": "permission_denied",
                        "attempts": [
                            {
                                "attempt": number,
                                "offset_sec": offset,
                                "classification": "permission_denied",
                                "http_status": 403,
                                "error_code": "permission-denied",
                            }
                            for number, offset in enumerate((0, 15, 45), 1)
                        ],
                    }
                }
            )
            batch.finish_attempt("permission_denied")

            report_path, summary_path = batch.finalize()
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            report = report_path.read_text(encoding="utf-8")

            self.assertEqual(summary["outcomes"], {"accepted": 1, "permission_denied": 1})
            self.assertEqual(
                summary["health_classifications"],
                {"healthy": 1, "permission_denied": 1},
            )
            self.assertIn("成功候选", report)
            self.assertIn("权限拒绝候选", report)
            self.assertNotIn("success@example.com", report)
            self.assertNotIn("denied@example.com", report)

    def test_finish_accepts_already_redacted_host_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            batch = trace.AutomaticRegistrationTraceBatch(temporary, page_state_interval=60)
            attempt = batch.begin_attempt(worker_id=1, idx=1, slot=1, replacement=0)
            attempt.writer.network(
                "request",
                "tab",
                {
                    "requestId": "1",
                    "timestamp": 1.0,
                    "request": {
                        "method": "POST",
                        "url": "https://<redacted:secret>/data?v=%3Credacted%3E",
                    },
                },
            )
            attempt.writer.network(
                "response",
                "tab",
                {
                    "requestId": "1",
                    "timestamp": 1.1,
                    "response": {
                        "status": 200,
                        "url": "https://<redacted:secret>/data?v=%3Credacted%3E",
                    },
                },
            )

            result = batch.finish_attempt("accepted")
            report_path, _summary_path = batch.finalize()

            self.assertEqual(result["outcome"], "accepted")
            self.assertTrue(report_path.is_file())

    def test_rebuild_restores_missing_attempt_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            batch = trace.AutomaticRegistrationTraceBatch(temporary, page_state_interval=60)
            attempt = batch.begin_attempt(worker_id=1, idx=1, slot=1, replacement=0)
            batch.finish_attempt("accepted")
            _report_path, summary_path = batch.finalize()
            for name in ("metadata.json", "timeline.json", "report.md"):
                (attempt.directory / name).unlink()

            rebuilt_report, rebuilt_summary = trace.rebuild_batch_reports(batch.session_dir)

            self.assertEqual(rebuilt_summary, summary_path)
            self.assertTrue(rebuilt_report.is_file())
            self.assertTrue((attempt.directory / "metadata.json").is_file())
            self.assertTrue((attempt.directory / "timeline.json").is_file())
            self.assertTrue((attempt.directory / "report.md").is_file())


class TraceIsolationTests(unittest.TestCase):
    def test_trace_failure_is_logged_once_and_does_not_raise(self):
        class BrokenTrace:
            def finish_attempt(self, *_args, **_kwargs):
                raise ValueError("Port could not be cast to integer value as 'secret>'")

        gui = reg.GrokRegisterGUI.__new__(reg.GrokRegisterGUI)
        gui.behavior_trace = BrokenTrace()
        gui._trace_error_reported = False
        gui.log = MagicMock()

        first = gui._trace_call("finish_attempt", "accepted")
        second = gui._trace_call("finish_attempt", "accepted")

        self.assertIsNone(first)
        self.assertIsNone(second)
        gui.log.assert_called_once()
        self.assertIn("注册主流程继续", gui.log.call_args.args[0])


class TabPoolTraceObserverTests(unittest.TestCase):
    def test_release_notifies_observer_before_browser_close(self):
        events = []

        class Observer:
            def browser_releasing(self, browser, tab):
                events.append(("observer", browser, tab))

        browser = object()
        tab = object()
        TabPool._thread_local.browser = browser
        TabPool._thread_local.tab = tab
        TabPool._thread_local.served = 0
        TabPool._all_browsers = [browser]
        TabPool._failed_closes.clear()
        TabPool._permanent_block = False
        TabPool._accept_new = True
        TabPool.set_lifecycle_observer(Observer())

        try:
            with patch("tab_pool.close_owned_browser", side_effect=lambda item: events.append(("close", item)) or True):
                self.assertTrue(TabPool.release_tab())
        finally:
            TabPool.set_lifecycle_observer(None)
            TabPool._thread_local.browser = None
            TabPool._thread_local.tab = None
            TabPool._all_browsers = []

        self.assertEqual(events[0], ("observer", browser, tab))
        self.assertEqual(events[1], ("close", browser))


if __name__ == "__main__":
    unittest.main()
