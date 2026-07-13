"""Structured CPA mint error codes for logs and failure ledgers."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

# Stable codes — use in JSONL / result dicts; message stays human-readable.
MISSING_EMAIL = "MISSING_EMAIL"
MISSING_CREDENTIALS = "MISSING_CREDENTIALS"
PROTOCOL_ONLY_NO_SSO = "PROTOCOL_ONLY_NO_SSO"
PROTOCOL_ONLY_FAIL = "PROTOCOL_ONLY_FAIL"
PROTOCOL_NO_SSO = "PROTOCOL_NO_SSO"
PROTOCOL_SSO_INVALID = "PROTOCOL_SSO_INVALID"
PROTOCOL_NETWORK = "PROTOCOL_NETWORK"
PROTOCOL_DEVICE_CODE = "PROTOCOL_DEVICE_CODE"
PROTOCOL_VERIFY = "PROTOCOL_VERIFY"
PROTOCOL_APPROVE = "PROTOCOL_APPROVE"
PROTOCOL_TOKEN = "PROTOCOL_TOKEN"
PROTOCOL_CANCELLED = "PROTOCOL_CANCELLED"
PROTOCOL_IMPORT = "PROTOCOL_IMPORT"
PROTOCOL_FAIL = "PROTOCOL_FAIL"
BROWSER_FAIL = "BROWSER_FAIL"
PROBE_NO_GROK45 = "PROBE_NO_GROK45"
PROBE_CHAT_FAIL = "PROBE_CHAT_FAIL"
EXPORT_DISABLED = "EXPORT_DISABLED"
IMPORT_FAIL = "IMPORT_FAIL"
UNKNOWN = "UNKNOWN"


def classify_protocol_message(msg: str) -> str:
    """Map protocol exception text to a stable error_code."""
    m = (msg or "").lower()
    if "curl_cffi not installed" in m:
        return PROTOCOL_IMPORT
    if "empty sso" in m or "missing sso" in m:
        return PROTOCOL_NO_SSO
    if "sso invalid" in m:
        return PROTOCOL_SSO_INVALID
    if "accounts.x.ai network" in m or "network error" in m:
        return PROTOCOL_NETWORK
    if "device code" in m:
        return PROTOCOL_DEVICE_CODE
    if "device/verify" in m or "verification_uri" in m:
        return PROTOCOL_VERIFY
    if "device/approve" in m:
        return PROTOCOL_APPROVE
    if "token poll" in m or "device auth" in m:
        return PROTOCOL_TOKEN
    if "cancelled" in m:
        return PROTOCOL_CANCELLED
    return PROTOCOL_FAIL


def classify_export_error(error: str | None, *, mint_method: str | None = None) -> str:
    """Best-effort classify a mint/export error string."""
    err = (error or "").strip()
    if not err:
        return UNKNOWN
    low = err.lower()
    if low.startswith("protocol_only"):
        return PROTOCOL_ONLY_FAIL
    if "protocol_only but no sso" in low:
        return PROTOCOL_ONLY_NO_SSO
    if "missing email/password" in low or "missing email" in low:
        return MISSING_CREDENTIALS
    if "grok-4.5 not listed" in low:
        return PROBE_NO_GROK45
    if "chat probe failed" in low:
        return PROBE_CHAT_FAIL
    if mint_method == "protocol" or low.startswith("protocol"):
        return classify_protocol_message(err)
    if "protocol:" in low:
        # browser fail that also carries protocol error
        return BROWSER_FAIL
    return BROWSER_FAIL if mint_method == "browser" else UNKNOWN


def append_failure_jsonl(
    path: str | Path,
    record: dict[str, Any],
) -> None:
    """Append one JSON object per line; never raise to callers."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        row = dict(record)
        row.setdefault("ts", int(time.time()))
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass
