from __future__ import annotations

import unittest
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
            self.page.listen.queue.append(
                _Packet(
                    self.page.birth_status,
                    "https://grok.com/rest/auth/set-birth-date",
                )
            )
            if 200 <= self.page.birth_status < 300:
                self.page.listen.queue.append(
                    _Packet(
                        200,
                        "https://grok.com/rest/app-chat/conversations/new",
                    )
                )

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
        if self.page.already_activated:
            self.page.listen.queue.append(
                _Packet(200, "https://grok.com/rest/app-chat/conversations/new")
            )
        else:
            self.page.birth_visible = True


class _Page:
    def __init__(self, *, already_activated=False, birth_status=200, message_error=False):
        self.url = "https://grok.com/"
        self.already_activated = already_activated
        self.birth_status = birth_status
        self.message_error = message_error
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

        page = Page()

        def complete_redirect(*_args, **_kwargs):
            page.url = "https://grok.com/"

        with patch.object(reg, "_get_page", return_value=page), patch.object(
            reg, "human_sleep", side_effect=complete_redirect
        ):
            result = reg.wait_for_sso_cookie(timeout=5)

        self.assertEqual(result, "token")

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


if __name__ == "__main__":
    unittest.main()
