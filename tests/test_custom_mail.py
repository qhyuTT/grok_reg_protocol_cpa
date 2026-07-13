import unittest
import tempfile
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch

from custom_mail import (
    CustomMailPool,
    message_matches,
    normalize_app_password,
    parse_credential_line,
)


class CredentialParsingTests(unittest.TestCase):
    def test_parse_valid_credential(self):
        credential = parse_credential_line(
            "example.com----inbox@gmail.com----abcd efgh ijkl mnop\n"
        )

        self.assertEqual(credential["domain"], "example.com")
        self.assertEqual(credential["mailbox"], "inbox@gmail.com")
        self.assertEqual(credential["app_password"], "abcd efgh ijkl mnop")

    def test_parse_rejects_missing_fields(self):
        for line in (
            "example.com----inbox@gmail.com",
            "----inbox@gmail.com----abcdefghijklmnop",
            "example.com--------abcdefghijklmnop",
            "example.com----not-an-email----abcdefghijklmnop",
        ):
            with self.subTest(line=line):
                self.assertIsNone(parse_credential_line(line))

    def test_normalize_app_password_removes_all_whitespace(self):
        self.assertEqual(
            normalize_app_password(" abcd efgh\tijkl\nmnop "),
            "abcdefghijklmnop",
        )


class CustomMailPoolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.credentials = self.root / "credentials.txt"
        self.used = self.root / "used.txt"

    def make_pool(self, credential_lines, **overrides):
        self.credentials.write_text("\n".join(credential_lines) + "\n", encoding="utf-8")
        config = {
            "custom_mail_accounts_file": str(self.credentials),
            "custom_mail_address_prefix": "reg",
            "custom_mail_max_addresses_per_account": 2,
        }
        config.update(overrides)
        return CustomMailPool(config, (str(self.used),))

    def test_load_accounts_ignores_comments_invalid_and_duplicate_domains(self):
        pool = self.make_pool(
            [
                "# comment",
                "// another comment",
                "invalid",
                "Example.com----first@gmail.com----aaaa bbbb cccc dddd",
                "example.com----duplicate@gmail.com----eeee ffff gggg hhhh",
            ]
        )

        accounts = pool.load_accounts()

        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["domain"], "example.com")
        self.assertEqual(accounts[0]["mailbox"], "first@gmail.com")

    def test_allocate_is_sequential_and_token_does_not_contain_credentials(self):
        pool = self.make_pool(["example.com----inbox@gmail.com----aaaa bbbb cccc dddd"])

        first, first_token = pool.allocate()
        second, second_token = pool.allocate()

        self.assertEqual(first, "reg000001@example.com")
        self.assertEqual(second, "reg000002@example.com")
        self.assertTrue(first_token.startswith("custommail:"))
        self.assertNotIn("inbox@gmail.com", first_token)
        self.assertNotIn("aaaabbbbccccdddd", first_token)
        self.assertNotEqual(first_token, second_token)

    def test_allocate_counts_ledger_entries_and_switches_domain_at_capacity(self):
        self.used.write_text(
            "reg000001@example.com--------ok\nreg000002@example.com--------failed\n",
            encoding="utf-8",
        )
        pool = self.make_pool(
            [
                "example.com----first@gmail.com----aaaa bbbb cccc dddd",
                "example.net----second@gmail.com----eeee ffff gggg hhhh",
            ]
        )

        address, _ = pool.allocate()

        self.assertEqual(address, "reg000001@example.net")

    def test_release_makes_unpersisted_address_available_again(self):
        pool = self.make_pool(["example.com----inbox@gmail.com----aaaa bbbb cccc dddd"])
        address, _ = pool.allocate()

        pool.release(address)
        reallocated, _ = pool.allocate()

        self.assertEqual(reallocated, address)

    def test_get_code_uses_readonly_imap_and_normalized_password(self):
        pool = self.make_pool(["example.com----inbox@gmail.com----aaaa bbbb cccc dddd"])
        address, token = pool.allocate()
        msg = EmailMessage()
        msg["From"] = "XAI <verification@x.ai>"
        msg["X-Original-To"] = address
        msg["Date"] = format_datetime(datetime.now(timezone.utc))
        msg["Subject"] = "Verification code 123456"
        msg.set_content("Your verification code is 123456")

        class FakeImap:
            def __init__(self, *args, **kwargs):
                self.login_args = None
                self.select_args = None
                self.fetch_args = None

            def login(self, *args):
                self.login_args = args

            def select(self, *args, **kwargs):
                self.select_args = (args, kwargs)
                return "OK", []

            def search(self, *args):
                return "OK", [b"1"]

            def fetch(self, *args):
                self.fetch_args = args
                return "OK", [(b"1", msg.as_bytes())]

            def close(self):
                return None

            def logout(self):
                return None

        fake = FakeImap()
        with patch("custom_mail.imaplib.IMAP4_SSL", return_value=fake):
            code = pool.get_code(
                token,
                address,
                lambda text, subject="": "123456" if "123456" in text else None,
                timeout=1,
            )

        self.assertEqual(code, "123456")
        self.assertEqual(fake.login_args, ("inbox@gmail.com", "aaaabbbbccccdddd"))
        self.assertEqual(fake.select_args, (("INBOX",), {"readonly": True}))
        self.assertEqual(fake.fetch_args, (b"1", "(BODY.PEEK[])"))


class MessageMatchingTests(unittest.TestCase):
    TARGET = "reg000001@example.com"
    NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)

    def make_message(
        self,
        *,
        sender="XAI <verification@x.ai>",
        recipient=None,
        recipient_header="X-Original-To",
        sent_at=None,
    ):
        msg = EmailMessage()
        msg["From"] = sender
        target = recipient or self.TARGET
        msg["To"] = target if recipient_header == "To" else "inbox@gmail.com"
        if recipient_header != "To":
            msg[recipient_header] = target
        msg["Date"] = format_datetime(sent_at or self.NOW)
        msg["Subject"] = "Your verification code is 123456"
        msg.set_content("Your verification code is 123456")
        return msg

    def test_accepts_allowed_sender_and_original_recipient(self):
        msg = self.make_message()

        self.assertTrue(
            message_matches(msg, self.TARGET, ["x.ai", "grok.com"], self.NOW.timestamp() - 1)
        )

    def test_accepts_supported_recipient_headers(self):
        for header in (
            "To",
            "Cc",
            "Delivered-To",
            "X-Original-To",
            "Original-Recipient",
            "Envelope-To",
        ):
            with self.subTest(header=header):
                msg = self.make_message(recipient_header=header)
                self.assertTrue(
                    message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() - 1)
                )

    def test_rejects_different_original_recipient(self):
        msg = self.make_message(recipient="reg000002@example.com")

        self.assertFalse(
            message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() - 1)
        )

    def test_rejects_sender_domain_suffix_spoofing(self):
        msg = self.make_message(sender="XAI <verification@evilx.ai>")

        self.assertFalse(
            message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() - 1)
        )

    def test_accepts_subdomain_of_allowed_sender_domain(self):
        msg = self.make_message(sender="XAI <verification@mail.x.ai>")

        self.assertTrue(
            message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() - 1)
        )

    def test_rejects_message_older_than_request(self):
        msg = self.make_message()

        self.assertFalse(
            message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() + 1)
        )

    def test_matches_recipient_case_insensitively(self):
        msg = self.make_message(recipient=self.TARGET.upper())

        self.assertTrue(
            message_matches(msg, self.TARGET, ["x.ai"], self.NOW.timestamp() - 1)
        )


if __name__ == "__main__":
    unittest.main()
