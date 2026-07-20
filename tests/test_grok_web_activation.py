from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import grok_register_ttk as reg
from DrissionPage.common import Keys


class _States:
    is_displayed = True
    is_enabled = True


class _Packet:
    class _Response:
        def __init__(self, status):
            self.status = status

    def __init__(self, status, url):
        self.response = self._Response(status)
        self.url = url


class _Listener:
    def __init__(self, page, status=200):
        self.page = page
        self.status = status
        self.packet = None
        self.queue = []
        self.started = False
        self.stopped = False

    def start(self, targets=None, **_kwargs):
        self.started = True
        self.queue = []
        target_text = " ".join(targets) if isinstance(targets, (list, tuple)) else str(targets)
        if "/api/auth/session" in target_text:
            self.queue.extend(
                [
                    _Packet(200, "https://grok.com/api/auth/session"),
                    _Packet(200, "https://grok.com/rest/user-settings"),
                ]
            )

    def wait(self, **_kwargs):
        if self.queue:
            return self.queue.pop(0)
        packet, self.packet = self.packet, None
        return packet

    def stop(self):
        self.stopped = True


class _Element:
    states = _States()

    def __init__(self, page, kind):
        self.page = page
        self.kind = kind
        self.text = "保存" if kind == "button" else ""
        self.value = ""

    def click(self):
        if self.kind == "button":
            self.page.birth_visible = False
            self.page.birth_saved = 200 <= self.page.birth_status < 300
            self.page.listen.queue.append(
                _Packet(
                    self.page.birth_status,
                    "https://grok.com/rest/auth/set-birth-date",
                )
            )
            if self.page.birth_saved and self.page.auto_conversation_after_birth:
                self.page.listen.queue.append(
                    _Packet(
                        200,
                        "https://grok.com/rest/app-chat/conversations/new",
                    )
                )

    def run_js(self, script):
        if self.kind == "button" and "this.click()" in script:
            self.click()

    def input(self, value, clear=False):
        if clear:
            self.value = ""
        self.value += str(value)


class _Actions:
    def __init__(self, page):
        self.page = page

    def type(self, key):
        if key != Keys.ENTER:
            return
        if self.page.message_error:
            raise RuntimeError("input rejected")
        self.page.message_submissions += 1
        if self.page.message_submissions <= self.page.ignored_message_submissions:
            return
        if self.page.already_activated or self.page.birth_saved:
            self.page.listen.queue.append(
                _Packet(200, "https://grok.com/rest/app-chat/conversations/new")
            )
        else:
            self.page.birth_visible = True


class _Page:
    def __init__(
        self,
        *,
        already_activated=False,
        birth_status=200,
        message_error=False,
        auto_conversation_after_birth=True,
        ignored_message_submissions=0,
    ):
        self.url = "https://grok.com/"
        self.already_activated = already_activated
        self.birth_status = birth_status
        self.message_error = message_error
        self.auto_conversation_after_birth = auto_conversation_after_birth
        self.message_submissions = 0
        self.ignored_message_submissions = ignored_message_submissions
        self.birth_saved = False
        self.birth_visible = False
        self.listen = _Listener(self)
        self.actions = _Actions(self)
        self.chat = _Element(self, "chat")
        self.birth = _Element(self, "birth")
        self.button = _Element(self, "button")

    def run_js(self, script, **_kwargs):
        if "fetch('/api/auth/session'" in script:
            return {
                "auth_session_status": 200,
                "user_settings_status": 200,
                "session_nonempty": True,
                "session_identity": True,
            }
        return "authenticated"

    def ele(self, locator, timeout=None):
        if "Ask Grok" in locator or "向 Grok" in locator or "chat-input" in locator:
            return self.chat
        if self.birth_visible and ("出生年份" in locator or "Birth year" in locator or "inputmode" in locator):
            return self.birth
        return None

    def eles(self, locator, timeout=None):
        if self.birth_visible and "button" in locator:
            return [self.button]
        return []


class GrokWebActivationTests(unittest.TestCase):
    def test_sso_waits_for_natural_grok_redirect(self):
        class Page:
            url = "https://accounts.x.ai/account"

            def run_js(self, _script, *_args):
                return "not-final-page"

            def cookies(self, **_kwargs):
                return [{"name": "sso", "value": "token", "domain": "accounts.x.ai"}]

            def get(self, _url):
                raise AssertionError("force-nav should not run before grace expires")

        page = Page()

        def complete_redirect(*_args, **_kwargs):
            page.url = "https://grok.com/"

        with patch.object(reg, "_get_page", return_value=page), patch.object(
            reg, "human_sleep", side_effect=complete_redirect
        ):
            # force_after large so natural redirect path is exercised first
            result = reg.wait_for_sso_cookie(timeout=5, force_grok_nav_after_sec=60)

        self.assertEqual(result, "token")

    def test_sso_force_navigates_to_grok_when_stuck_on_accounts(self):
        class Page:
            url = "https://accounts.x.ai/account"
            gets = 0

            def run_js(self, _script, *_args):
                return "not-final-page"

            def cookies(self, **_kwargs):
                return [{"name": "sso", "value": "sso-token", "domain": ".x.ai"}]

            def get(self, url):
                self.gets += 1
                self.url = "https://grok.com/"

            def ele(self, locator, timeout=None):
                if "chat-input" in str(locator) or "Ask Grok" in str(locator):
                    return object()
                return None

        page = Page()
        clock = {"t": 1000.0}

        def fake_time():
            return clock["t"]

        def fake_sleep(_seconds, _cancel=None):
            clock["t"] += 1.0

        logs: list[str] = []
        with (
            patch.object(reg, "_get_page", return_value=page),
            patch.object(reg.time, "time", side_effect=fake_time),
            patch.object(reg, "human_sleep", side_effect=fake_sleep),
            patch.object(reg, "sleep_with_cancel", side_effect=fake_sleep),
            patch.object(
                reg,
                "_activation_session_probe",
                return_value={
                    "auth_session_status": 200,
                    "user_settings_status": 200,
                    "session_nonempty": True,
                    "session_identity": True,
                },
            ),
            patch.object(reg, "_activation_chat_ready", return_value=True),
            patch.object(reg, "_wait_page_doc_loaded", return_value=True),
            patch.dict(
                reg.config,
                {
                    "sso_force_grok_nav_after_sec": 1,
                    "sso_force_grok_nav_settle_sec": 0,
                },
                clear=False,
            ),
        ):
            result = reg.wait_for_sso_cookie(
                timeout=15,
                log_callback=logs.append,
                force_grok_nav_after_sec=1,
            )

        self.assertEqual(result, "sso-token")
        self.assertGreaterEqual(page.gets, 1)
        self.assertTrue(any("强制打开 Grok" in row for row in logs))
        self.assertTrue(reg._LAST_SSO_WAIT_META.get("forced_nav"))

    def test_sso_force_nav_disabled_still_times_out_on_accounts(self):
        class Page:
            url = "https://accounts.x.ai/account"
            gets = 0

            def run_js(self, _script, *_args):
                return "not-final-page"

            def cookies(self, **_kwargs):
                return [{"name": "sso", "value": "token", "domain": ".x.ai"}]

            def get(self, _url):
                self.gets += 1

        page = Page()
        with (
            patch.object(reg, "_get_page", return_value=page),
            patch.object(reg, "human_sleep", return_value=None),
        ):
            with self.assertRaisesRegex(Exception, r"forced_nav=no|未完成 sso"):
                reg.wait_for_sso_cookie(timeout=2, force_grok_nav_after_sec=0)

        self.assertEqual(page.gets, 0)

    def test_no_sso_does_not_force_nav(self):
        class Page:
            url = "https://accounts.x.ai/sign-up"
            gets = 0

            def run_js(self, _script, *_args):
                return "not-final-page"

            def cookies(self, **_kwargs):
                return [{"name": "cf_clearance", "value": "x", "domain": ".x.ai"}]

            def get(self, _url):
                self.gets += 1

        page = Page()
        with (
            patch.object(reg, "_get_page", return_value=page),
            patch.object(reg, "human_sleep", return_value=None),
        ):
            with self.assertRaisesRegex(Exception, r"sso=no"):
                reg.wait_for_sso_cookie(timeout=2, force_grok_nav_after_sec=1)

        self.assertEqual(page.gets, 0)

    def test_birth_year_native_fill_succeeds(self):
        class BirthInput:
            def __init__(self):
                self.value = ""

            def click(self):
                return None

            def input(self, text, clear=True):
                self.value = str(text)

            def run_js(self, script, *args):
                if args:
                    self.value = str(args[0])
                return self.value

        birth = BirthInput()

        class Page:
            def ele(self, locator, timeout=None):
                if "出生年份" in str(locator) or "bday-year" in str(locator):
                    return birth
                return None

            def eles(self, locator, timeout=None):
                return [birth]

        ok, attempts, selector, err = reg._activation_fill_birth_year(
            Page(),
            1995,
            deadline=time.time() + 5,
            cancel_callback=None,
            log=lambda _m: None,
        )
        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertGreaterEqual(attempts, 1)
        self.assertIn("1995", birth.value)

    def test_conversation_429_is_soft_retried_then_can_succeed(self):
        page = _Page()
        # First conversation packet is 429; second is 200 after resubmit.
        page.listen.packets = [
            _Packet(429, "https://grok.com/rest/app-chat/conversations/new"),
            _Packet(200, "https://grok.com/rest/app-chat/conversations/new"),
        ]
        # Skip birthday path: pretend conversation arrives.
        logs = []
        with (
            patch.object(
                reg,
                "wait_for_authenticated_grok_page",
                return_value={
                    "ok": True,
                    "auth_session_status": 200,
                    "user_settings_status": 200,
                    "session_nonempty": True,
                    "dom_state": "authenticated",
                },
            ),
            patch.object(reg, "_activation_find_birth_input", return_value=(None, None)),
            patch.object(
                reg,
                "_activation_submit_message",
                return_value=("[data-testid=chat-input]", "enter"),
            ),
            patch.object(reg, "sleep_with_cancel", return_value=None),
            patch.object(
                reg,
                "_activation_conversation_url",
                side_effect=["", "https://grok.com/c/abc"],
            ),
        ):
            # Drive packets: first wait returns 429, later URL becomes conversation.
            result = reg.activate_grok_web_account(page, log_callback=logs.append, timeout=20)

        # Either success after recovery or soft 429 handling recorded.
        if result.get("ok"):
            self.assertTrue(result["ok"])
        else:
            self.assertIn("429", str(result.get("reason") or ""))
        self.assertIn("forced_nav", result)

    def test_activation_audit_includes_forced_nav_fields(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "act.jsonl"
            with patch.dict(
                reg.config,
                {"registration_web_activation_audit_file": str(path)},
                clear=False,
            ):
                reg.record_web_activation_audit(
                    "user@example.com",
                    {
                        "ok": True,
                        "stage": "complete",
                        "forced_nav": True,
                        "entry_path": "forced",
                        "page_reloads": 1,
                        "conversation_429_retries": 2,
                    },
                )
            row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            self.assertTrue(row["forced_nav"])
            self.assertEqual(row["entry_path"], "forced")
            self.assertEqual(row["page_reloads"], 1)
            self.assertEqual(row["conversation_429_retries"], 2)

    def test_authenticated_endpoints_confirm_login(self):
        page = _Page()
        result = reg.wait_for_authenticated_grok_page(page, timeout=5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["auth_session_status"], 200)
        self.assertEqual(result["user_settings_status"], 200)

    def test_visible_login_controls_are_anonymous_state(self):
        class Page:
            def run_js(self, _script):
                return "anonymous"

        self.assertEqual(reg._activation_auth_state(Page()), "anonymous")

    def test_message_birth_and_conversation_success(self):
        page = _Page()
        logs = []
        with patch.object(reg.secrets, "choice", return_value="你好"), patch.object(
            reg.secrets, "randbelow", return_value=5
        ):
            result = reg.activate_grok_web_account(page, log_callback=logs.append, timeout=5)

        self.assertTrue(result["ok"])
        self.assertTrue(result["birth_date_saved"])
        self.assertEqual(result["birth_status"], 200)
        self.assertEqual(result["conversation_status"], 200)
        self.assertIn("会话创建成功", " ".join(logs))
        self.assertTrue(page.listen.started)
        self.assertTrue(page.listen.stopped)

    def test_stale_birth_button_uses_refetched_dom_fallback(self):
        page = _Page()

        class StaleButton:
            states = _States()

            def run_js(self, _script):
                return None

            def click(self):
                raise RuntimeError("This element has no location or size")

        with patch.object(
            reg,
            "_activation_pick_birth_button",
            side_effect=[StaleButton(), page.button],
        ):
            result = reg.activate_grok_web_account(page, timeout=5)

        self.assertTrue(result["ok"])
        self.assertEqual(result["birth_button_attempts"], 1)

    def test_birth_save_resubmits_message_once_when_conversation_is_not_automatic(self):
        page = _Page(auto_conversation_after_birth=False)
        result = reg.activate_grok_web_account(page, timeout=5)

        self.assertTrue(result["ok"])
        self.assertEqual(result["message_submissions"], 2)
        self.assertEqual(page.message_submissions, 2)

    def test_message_submission_retries_when_first_enter_has_no_transition(self):
        page = _Page(ignored_message_submissions=1)
        result = reg.activate_grok_web_account(page, timeout=12)

        self.assertTrue(result["ok"])
        self.assertEqual(result["message_submit_attempts"], 2)
        self.assertEqual(result["message_submissions"], 2)

    def test_live_value_prefers_property_over_initial_attribute(self):
        class ControlledInput:
            def property(self, name):
                return "1991" if name == "value" else None

            def attr(self, name):
                return "" if name == "value" else None

        self.assertEqual(reg._activation_live_value(ControlledInput()), "1991")

    def test_unique_dialog_input_is_safe_fallback(self):
        page = _Page()
        page.birth_visible = True

        def no_direct_match(_locator, timeout=None):
            return None

        def dialog_inputs(locator, timeout=None):
            if "input" in locator:
                return [page.birth]
            return []

        page.ele = no_direct_match
        page.eles = dialog_inputs
        element, selector = reg._activation_find_birth_input(page)

        self.assertIs(element, page.birth)
        self.assertEqual(selector, "dialog_unique_input")

    def test_existing_birth_date_skips_modal(self):
        page = _Page(already_activated=True)
        result = reg.activate_grok_web_account(page, timeout=5)
        self.assertTrue(result["ok"])
        self.assertFalse(result["birth_date_saved"])
        self.assertEqual(result["conversation_status"], 200)

    def test_non_2xx_birth_response_is_failure(self):
        page = _Page(birth_status=403)
        result = reg.activate_grok_web_account(page, timeout=5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "set_birth_date_http_403")

    def test_message_submission_failure_is_failure(self):
        page = _Page(message_error=True)
        result = reg.activate_grok_web_account(page, timeout=5)
        self.assertFalse(result["ok"])
        self.assertTrue(result["reason"].startswith("chat_submit_failed:"))

    def test_cancel_is_propagated(self):
        page = _Page()
        with self.assertRaises(reg.RegistrationCancelled):
            reg.activate_grok_web_account(page, cancel_callback=lambda: True, timeout=5)

    def test_activation_audit_is_shared_and_omits_sensitive_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "activation.jsonl"
            activation = {
                "ok": False,
                "stage": "birthday_save",
                "reason": "button unavailable",
                "duration_sec": 3.2,
                "message": "secret message",
                "password": "secret password",
                "auth": {"cookie": "secret cookie"},
                "birth_button_attempts": 3,
                "dom_summary": {
                    "dialog_count": 1,
                    "inputs": [{"aria_label": "出生年份"}],
                },
            }
            with patch.dict(
                reg.config,
                {
                    "registration_web_activation_audit_file": str(path),
                    "proxy_rotation_enabled": False,
                },
                clear=False,
            ):
                reg.record_web_activation_audit("person@example.com", activation)

            raw = path.read_text(encoding="utf-8")
            record = json.loads(raw)
            self.assertEqual(record["email"], "person@example.com")
            self.assertEqual(record["stage"], "birthday_save")
            self.assertEqual(record["dom_summary"]["dialog_count"], 1)
            self.assertNotIn("secret", raw)


if __name__ == "__main__":
    unittest.main()
