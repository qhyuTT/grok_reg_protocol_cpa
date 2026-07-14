"""Custom catch-all domain mail provider backed by Gmail IMAP."""

from __future__ import annotations

import email as email_lib
import imaplib
import os
import re
import secrets
import threading
import time
from datetime import timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime


def parse_credential_line(line: str):
    parts = line.rstrip("\n").split("----", 2)
    if len(parts) != 3:
        return None
    domain, mailbox, app_password = (part.strip() for part in parts)
    domain = domain.lower().lstrip("@")
    if not domain or "." not in domain or "@" not in mailbox or not app_password:
        return None
    return {"domain": domain, "mailbox": mailbox, "app_password": app_password}


def normalize_app_password(value: str) -> str:
    return re.sub(r"\s+", "", str(value or ""))


def _decode(value) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _body(msg) -> str:
    def decode_part(part):
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        return payload.decode(part.get_content_charset() or "utf-8", errors="ignore")

    if not msg.is_multipart():
        return decode_part(msg)
    plain, html = "", ""
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            continue
        if part.get_content_type() == "text/plain" and not plain:
            plain = decode_part(part)
        elif part.get_content_type() == "text/html" and not html:
            html = decode_part(part)
    return plain or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


RECIPIENT_HEADERS = ("To", "Cc", "Delivered-To", "X-Original-To", "Original-Recipient", "Envelope-To")


def message_matches(msg, target_email: str, allowed_domains, not_before_ts: float) -> bool:
    date_str = msg.get("Date")
    if date_str:
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt.timestamp() < not_before_ts:
                return False
        except Exception:
            pass

    target = target_email.strip().lower()
    recipient_blob = " ".join(_decode(msg.get(name, "")) for name in RECIPIENT_HEADERS).lower()
    if not target or target not in recipient_blob:
        return False

    sender_addresses = [addr.lower() for _, addr in getaddresses([_decode(msg.get("From", ""))]) if addr]
    allowed = [str(d).strip().lower().lstrip("@") for d in allowed_domains if str(d).strip()]
    for addr in sender_addresses:
        domain = addr.rsplit("@", 1)[-1]
        if any(domain == item or domain.endswith("." + item) for item in allowed):
            return True
    return False


class CustomMailCapacityExhausted(RuntimeError):
    """Raised when every configured CustomMail domain has reached its limit."""

    def __init__(self, *, total: int, consumed: int):
        self.total = int(total)
        self.consumed = int(consumed)
        self.remaining = max(0, self.total - self.consumed)
        super().__init__(
            "CustomMail 可用地址已耗尽，请增加容量或补充凭证"
            f"（已用 {self.consumed}/{self.total}）"
        )


class CustomMailPool:
    def __init__(self, config: dict, used_files=()):
        self.config = config
        self.used_files = tuple(used_files)
        self._lock = threading.Lock()
        self._reserved = set()
        self._tokens = {}

    def _path(self):
        raw = str(self.config.get("custom_mail_accounts_file", "custom_mail_credentials.txt") or "")
        if os.path.isabs(raw):
            return raw
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), raw)

    def load_accounts(self):
        path = self._path()
        if not os.path.isfile(path):
            raise Exception(f"CustomMail 凭证文件不存在: {path}")
        accounts, seen = [], set()
        with open(path, encoding="utf-8-sig") as handle:
            for line_no, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                item = parse_credential_line(raw)
                if not item:
                    print(f"[CustomMail] 跳过无效凭证行 {line_no}")
                    continue
                if item["domain"] in seen:
                    print(f"[CustomMail] 跳过重复域名行 {line_no}: {item['domain']}")
                    continue
                seen.add(item["domain"])
                accounts.append(item)
        if not accounts:
            raise Exception(f"CustomMail 凭证文件无有效记录: {path}")
        return accounts

    def _tracked(self):
        result = set(self._reserved)
        for path in self.used_files:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    for line in handle:
                        value = line.split("----", 1)[0].strip().lower()
                        if "@" in value:
                            result.add(value)
            except OSError:
                continue
        return result

    def _capacity_unlocked(self):
        accounts = self.load_accounts()
        maximum = max(1, int(self.config.get("custom_mail_max_addresses_per_account", 100) or 100))
        tracked = self._tracked()
        consumed = sum(
            min(maximum, sum(1 for addr in tracked if addr.endswith("@" + account["domain"])))
            for account in accounts
        )
        total = len(accounts) * maximum
        return {
            "accounts": len(accounts),
            "per_account": maximum,
            "total": total,
            "consumed": consumed,
            "remaining": max(0, total - consumed),
        }

    def capacity(self):
        """Return a consistent snapshot of configured and remaining addresses."""
        with self._lock:
            return self._capacity_unlocked()

    def allocate(self):
        prefix = re.sub(r"[^a-z0-9_-]", "", str(self.config.get("custom_mail_address_prefix", "reg")).lower()) or "reg"
        maximum = max(1, int(self.config.get("custom_mail_max_addresses_per_account", 100) or 100))
        with self._lock:
            tracked = self._tracked()
            for account in self.load_accounts():
                domain = account["domain"]
                consumed = {addr for addr in tracked if addr.endswith("@" + domain)}
                if len(consumed) >= maximum:
                    continue
                for index in range(1, maximum + 1):
                    address = f"{prefix}{index:06d}@{domain}"
                    if address in tracked:
                        continue
                    self._reserved.add(address)
                    token = "custommail:" + secrets.token_urlsafe(18)
                    self._tokens[token] = {"account": account, "email": address, "created_at": time.time()}
                    return address, token
            capacity = self._capacity_unlocked()
        raise CustomMailCapacityExhausted(
            total=capacity["total"], consumed=capacity["consumed"]
        )

    def release(self, email: str):
        with self._lock:
            self._reserved.discard(str(email or "").strip().lower())

    def get_code(self, token, target_email, extract_code, timeout=180, poll_interval=5, log_callback=None, cancel_callback=None, resend_callback=None):
        info = self._tokens.get(token)
        if not info or info["email"].lower() != str(target_email).lower():
            raise Exception("CustomMail dev_token 无效或已过期")
        account = info["account"]
        recent = max(60, int(self.config.get("custom_mail_recent_seconds", 900) or 900))
        not_before = max(info["created_at"] - 30, time.time() - recent)
        last_n = max(1, int(self.config.get("custom_mail_imap_last_n", 50) or 50))
        allowed = re.split(r"[,，\s]+", str(self.config.get("custom_mail_allowed_sender_domains", "x.ai,grok.com") or ""))
        interval = max(1.0, float(self.config.get("custom_mail_poll_interval", poll_interval) or poll_interval))
        deadline, next_resend = time.time() + timeout, time.time() + 60
        while time.time() < deadline:
            if cancel_callback and cancel_callback():
                raise Exception("操作已取消")
            if resend_callback and time.time() >= next_resend:
                try:
                    resend_callback()
                except Exception:
                    pass
                next_resend = time.time() + 60
            try:
                imap = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=45)
                imap.login(account["mailbox"], normalize_app_password(account["app_password"]))
                try:
                    imap.select("INBOX", readonly=True)
                    status, data = imap.search(None, "ALL")
                    ids = data[0].split()[-last_n:] if status == "OK" and data and data[0] else []
                    for mid in reversed(ids):
                        _, raw = imap.fetch(mid, "(BODY.PEEK[])")
                        if not raw or not raw[0] or not isinstance(raw[0][1], bytes):
                            continue
                        msg = email_lib.message_from_bytes(raw[0][1])
                        if not message_matches(msg, target_email, allowed, not_before):
                            continue
                        subject = _decode(msg.get("Subject", ""))
                        code = extract_code(f"{subject}\n{_body(msg)}", subject)
                        if code:
                            if log_callback:
                                log_callback(f"[*] CustomMail 从 Gmail 提取到验证码: {code}")
                            return code
                finally:
                    try: imap.close()
                    except Exception: pass
                    try: imap.logout()
                    except Exception: pass
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] CustomMail Gmail IMAP 读取失败: {exc}")
            time.sleep(interval)
        raise Exception(f"CustomMail 在 {timeout}s 内未收到验证码邮件: {target_email}")
