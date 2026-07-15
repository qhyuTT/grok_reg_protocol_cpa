"""Record one manual Grok registration and build a redacted behavior report.

Raw browser events and CDP network payloads intentionally contain secrets.  They
are kept in a private ``raw`` directory, never echoed to the terminal, and are
deleted only after both redacted report files have been written successfully.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import re
import shutil
import threading
import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit


DEFAULT_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
DEFAULT_OUTPUT_DIR = "manual_registration_traces"
JS_BINDING_NAME = "__grokManualTrace"

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "email",
    "otp",
    "passcode",
    "password",
    "secret",
    "session",
    "sso",
    "token",
)
_SENSITIVE_BODY_KEYS = {
    "body",
    "html",
    "key",
    "outerhtml",
    "postdata",
    "requestbody",
    "responsebody",
    "response_body",
    "value",
}
_EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]+)@([\w.-]+\.[A-Za-z]{2,})(?![\w.-])")
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[^\s,;]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_COOKIE_VALUE_RE = re.compile(
    r"(?i)\b(sso|session|auth|authorization|token|cookie|secret)=([^;\s&,]+)"
)
_OTP_RE = re.compile(r"(?<!\d)\d{6,8}(?!\d)")
_LONG_SECRET_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_.-]{32,}(?![A-Za-z0-9])")
_DYNAMIC_ID_RE = re.compile(
    r"(?:^[0-9a-f]{12,}$|^[0-9a-f]{8}-[0-9a-f-]{20,}$|\d{6,}|react|radix|headlessui|:[a-z0-9]+:)",
    re.IGNORECASE,
)
_PATH_CODE_RE = re.compile(r"^(?=.{6,32}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._-]+$")
_SENSITIVE_PATH_PARENTS = {"callback", "code", "otp", "session", "token", "verify", "verification"}


class TraceRunError(RuntimeError):
    """Failure wrapper that exposes only the private artifact location."""

    def __init__(self, session_dir: Path, stage: str):
        super().__init__(f"manual trace failed during {stage}")
        self.session_dir = session_dir
        self.stage = stage


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _normalize_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def redact_url(url: str) -> str:
    """Redact query/fragment values while retaining a useful endpoint shape."""
    try:
        parsed = urlsplit(url)
    except (TypeError, ValueError):
        return _redact_plain_text(str(url))
    if not parsed.scheme or not parsed.netloc:
        return redact_text(str(url))
    query = urlencode([(key, "<redacted>") for key, _value in parse_qsl(parsed.query, keep_blank_values=True)])
    fragment = "<redacted>" if parsed.fragment else ""
    raw_netloc = parsed.netloc
    if raw_netloc.startswith("<redacted:") and raw_netloc.endswith(">"):
        safe_netloc = raw_netloc
    else:
        try:
            hostname = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            # A malformed raw URL or an already-redacted placeholder must not
            # turn report generation into a business-flow failure.
            safe_netloc = "<redacted:host>"
        else:
            if "<redacted:" in raw_netloc:
                safe_netloc = "<redacted:host>"
            else:
                safe_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
                safe_netloc = f"{safe_host}:{port}" if port else safe_host
    segments = []
    previous = ""
    for raw_segment in parsed.path.split("/"):
        segment = unquote(raw_segment)
        redacted = _redact_plain_text(segment)
        if previous.lower() in _SENSITIVE_PATH_PARENTS or _PATH_CODE_RE.fullmatch(segment):
            redacted = "<redacted>"
        segments.append(redacted)
        previous = segment
    safe_path = "/".join(segments)
    return urlunsplit((parsed.scheme, safe_netloc, safe_path, query, fragment))


def _redact_plain_text(value: str) -> str:
    text = _EMAIL_RE.sub("<redacted:email>", value)
    text = _BEARER_RE.sub(lambda match: f"{match.group(1)} <redacted:token>", text)
    text = _JWT_RE.sub("<redacted:token>", text)
    text = _COOKIE_VALUE_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = _OTP_RE.sub("<redacted:code>", text)
    return _LONG_SECRET_RE.sub("<redacted:secret>", text)


def redact_text(value: str) -> str:
    """Best-effort redaction for free-form report text."""
    text = str(value)
    if text.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(text)
            if parsed.scheme and parsed.netloc:
                text = redact_url(text)
        except (TypeError, ValueError):
            pass
    return _redact_plain_text(text)


def redact_sensitive(value: Any, key: object | None = None) -> Any:
    """Return a deeply redacted copy suitable for persistent reports/tests."""
    normalized_key = _normalize_key(key) if key is not None else ""
    if normalized_key in _SENSITIVE_BODY_KEYS:
        label = "input" if normalized_key in {"key", "value"} else "body"
        return f"<redacted:{label}>"
    if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
        return "<redacted:sensitive>"
    if isinstance(value, Mapping):
        return {str(item_key): redact_sensitive(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _css_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _attributes(target: Mapping[str, Any]) -> dict[str, Any]:
    attrs = target.get("attributes")
    return dict(attrs) if isinstance(attrs, Mapping) else {}


def _is_dynamic_id(value: str) -> bool:
    return bool(_DYNAMIC_ID_RE.search(value))


def stable_selector(target: Mapping[str, Any] | None) -> str:
    """Choose the most stable captured selector without using typed values."""
    if not target:
        return ""
    attrs = _attributes(target)
    tag = str(target.get("tag") or "*").lower()

    test_id = attrs.get("data-testid") or target.get("dataTestid")
    if test_id:
        return f'[{"data-testid"}={_css_string(test_id)}]'

    name = attrs.get("name") or target.get("name")
    if name:
        return f'{tag}[name={_css_string(name)}]'

    autocomplete = attrs.get("autocomplete") or target.get("autocomplete")
    if autocomplete:
        return f'{tag}[autocomplete={_css_string(autocomplete)}]'

    role = attrs.get("role") or target.get("role")
    aria_label = attrs.get("aria-label") or target.get("ariaLabel")
    if role and aria_label:
        return f'[role={_css_string(role)}][aria-label={_css_string(aria_label)}]'
    if role:
        return f'[role={_css_string(role)}]'
    if aria_label:
        return f'{tag}[aria-label={_css_string(aria_label)}]'

    element_id = attrs.get("id") or target.get("id")
    if element_id and not _is_dynamic_id(str(element_id)):
        return f'#{str(element_id).replace(" ", "\\ ")}'

    placeholder = attrs.get("placeholder") or target.get("placeholder")
    if placeholder:
        return f'{tag}[placeholder={_css_string(placeholder)}]'

    element_type = attrs.get("type") or target.get("type")
    if element_type and tag in {"button", "input"}:
        return f'{tag}[type={_css_string(element_type)}]'

    css_path = target.get("cssPath")
    return str(css_path or tag)


def _parse_recorded_at(record: Mapping[str, Any]) -> float:
    raw = record.get("recorded_at")
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _network_url(record: Mapping[str, Any]) -> str:
    payload = record.get("payload") or {}
    if not isinstance(payload, Mapping):
        return ""
    if isinstance(payload.get("request"), Mapping):
        return str(payload["request"].get("url") or "")
    if isinstance(payload.get("response"), Mapping):
        return str(payload["response"].get("url") or "")
    return str(payload.get("url") or "")


def summarize_trace(
    event_records: Iterable[Mapping[str, Any]],
    network_records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the compact, redacted summary used by both output artifacts."""
    events = list(event_records)
    network = list(network_records)
    event_counts: Counter[str] = Counter()
    selector_counts: Counter[str] = Counter()
    timeline: list[dict[str, Any]] = []
    timestamps: list[float] = []
    navigation_count = 0

    for record in events:
        recorded = _parse_recorded_at(record)
        if recorded:
            timestamps.append(recorded)
        payload = record.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        category = str(record.get("category") or "user")
        event_type = str(payload.get("type") or record.get("category") or "unknown")
        if category == "user":
            event_counts[event_type] += 1
        elif category == "navigation":
            navigation_count += 1
        else:
            continue
        selector = stable_selector(payload.get("target") if isinstance(payload.get("target"), Mapping) else None)
        if selector and category == "user":
            selector_counts[redact_text(selector)] += 1
        if event_type == "pointermove":
            continue
        entry = {
            "recorded_at": record.get("recorded_at"),
            "category": category,
            "action": event_type,
            "url": redact_url(str(payload.get("url") or "")) if payload.get("url") else "",
        }
        if selector:
            entry["selector"] = redact_text(selector)
        timeline.append(entry)

    requests: dict[str, dict[str, Any]] = {}
    response_by_request: dict[str, Mapping[str, Any]] = {}
    status_counts: Counter[str] = Counter()
    endpoint_stats: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "statuses": Counter(), "durations_ms": []}
    )

    for record in network:
        recorded = _parse_recorded_at(record)
        if recorded:
            timestamps.append(recorded)
        category = str(record.get("category") or "")
        payload = record.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        request_id = str(payload.get("requestId") or "")
        if category == "request":
            request = payload.get("request") if isinstance(payload.get("request"), Mapping) else {}
            requests[request_id] = {
                "method": str(request.get("method") or "GET"),
                "url": str(request.get("url") or ""),
                "timestamp": payload.get("timestamp"),
                "recorded_at": record.get("recorded_at"),
            }
        elif category == "response":
            response_by_request[request_id] = record

    for request_id, request in requests.items():
        method = request["method"]
        safe_url = redact_url(request["url"]) if request["url"] else ""
        response_record = response_by_request.get(request_id)
        status: int | None = None
        duration_ms: float | None = None
        if response_record:
            response_payload = response_record.get("payload") or {}
            response = response_payload.get("response") if isinstance(response_payload.get("response"), Mapping) else {}
            raw_status = response.get("status")
            if isinstance(raw_status, (int, float)):
                status = int(raw_status)
                status_counts[str(status)] += 1
            start = request.get("timestamp")
            end = response_payload.get("timestamp")
            if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
                duration_ms = round((end - start) * 1000, 1)
        stats = endpoint_stats[(method, safe_url)]
        stats["count"] += 1
        if status is not None:
            stats["statuses"][str(status)] += 1
        if duration_ms is not None:
            stats["durations_ms"].append(duration_ms)
        timeline.append(
            {
                "recorded_at": request.get("recorded_at"),
                "category": "network",
                "action": method,
                "url": safe_url,
                "status": status,
                "duration_ms": duration_ms,
            }
        )

    endpoints = []
    for (method, url), stats in endpoint_stats.items():
        durations = stats.pop("durations_ms")
        endpoints.append(
            {
                "method": method,
                "url": url,
                "count": stats["count"],
                "statuses": dict(stats["statuses"]),
                "average_duration_ms": round(sum(durations) / len(durations), 1) if durations else None,
            }
        )
    endpoints.sort(key=lambda item: (-item["count"], item["method"], item["url"]))
    timeline.sort(key=lambda item: str(item.get("recorded_at") or ""))
    selectors = [
        {"selector": selector, "count": count}
        for selector, count in selector_counts.most_common()
    ]
    duration = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    return {
        "generated_at": _now_iso(),
        "duration_seconds": round(max(0.0, duration), 3),
        "user_event_count": sum(event_counts.values()),
        "user_event_types": dict(event_counts),
        "navigation_count": navigation_count,
        "network_request_count": len(requests),
        "network_response_count": len(response_by_request),
        "response_statuses": dict(status_counts),
        "selectors": selectors,
        "endpoints": endpoints,
        "timeline": timeline,
    }


def _secure_open(path: Path, flags: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, flags, 0o600)
    os.chmod(path, 0o600)
    return fd


def _secure_write_text(path: Path, content: str) -> None:
    fd = _secure_open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _secure_write_json(path: Path, value: Any) -> None:
    _secure_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _secure_write_bytes(path: Path, content: bytes) -> None:
    fd = _secure_open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(item, dict):
                records.append(item)
    return records


def _markdown_cell(value: object) -> str:
    return redact_text(str(value)).replace("|", "\\|").replace("\n", " ")


def render_report(summary: Mapping[str, Any]) -> str:
    """Render a Markdown report containing no raw bodies, headers, or inputs."""
    lines = [
        "# 手动注册行为分析",
        "",
        f"- 生成时间：`{_markdown_cell(summary.get('generated_at', ''))}`",
        f"- 录制时长：`{summary.get('duration_seconds', 0)}` 秒",
        f"- 用户事件：`{summary.get('user_event_count', 0)}`",
        f"- 网络请求 / 响应：`{summary.get('network_request_count', 0)}` / `{summary.get('network_response_count', 0)}`",
        "",
        "## 用户操作分布",
        "",
    ]
    event_types = summary.get("user_event_types") or {}
    if event_types:
        for event_type, count in sorted(event_types.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- `{_markdown_cell(event_type)}`：{count}")
    else:
        lines.append("- 未捕获到用户事件。")

    lines.extend(["", "## 稳定选择器", ""])
    selectors = summary.get("selectors") or []
    if selectors:
        lines.extend(["| 次数 | 选择器 |", "| ---: | --- |"])
        for item in selectors[:50]:
            lines.append(f"| {item.get('count', 0)} | `{_markdown_cell(item.get('selector', ''))}` |")
    else:
        lines.append("未生成可用选择器。")

    lines.extend(["", "## 关键网络端点", ""])
    endpoints = summary.get("endpoints") or []
    if endpoints:
        lines.extend(["| 次数 | 方法 | 状态 | 平均耗时 | URL |", "| ---: | --- | --- | ---: | --- |"])
        for item in endpoints[:100]:
            statuses = ", ".join(f"{key}×{value}" for key, value in sorted((item.get("statuses") or {}).items())) or "-"
            duration = item.get("average_duration_ms")
            duration_text = f"{duration} ms" if duration is not None else "-"
            lines.append(
                f"| {item.get('count', 0)} | `{_markdown_cell(item.get('method', ''))}` | "
                f"{_markdown_cell(statuses)} | {duration_text} | `{_markdown_cell(item.get('url', ''))}` |"
            )
    else:
        lines.append("未捕获到网络请求。")

    lines.extend(["", "## 关键操作时间线", ""])
    operation_timeline = [
        item for item in (summary.get("timeline") or []) if item.get("category") in {"user", "navigation"}
    ]
    if operation_timeline:
        lines.extend(["| 时间 | 类型 | 操作 | 选择器 / URL |", "| --- | --- | --- | --- |"])
        for item in operation_timeline[:100]:
            target = item.get("selector") or item.get("url") or "-"
            lines.append(
                f"| `{_markdown_cell(item.get('recorded_at', ''))}` | "
                f"`{_markdown_cell(item.get('category', ''))}` | "
                f"`{_markdown_cell(item.get('action', ''))}` | `{_markdown_cell(target)}` |"
            )
    else:
        lines.append("未捕获到关键用户操作或导航。")

    lines.extend(
        [
            "",
            "## 自动化优化提示",
            "",
            "- 优先使用上表中重复出现的 `data-testid`、`name`、`autocomplete`、`role` 和 `aria-label` 选择器。",
            "- 用关键请求的响应状态或页面导航作为完成信号，减少固定 `sleep`。",
            "- `timeline.json` 可用于逐步对照当前自动化与人工流程；输入值、Cookie、Token 和正文均已移除。",
            "",
        ]
    )
    return "\n".join(lines)


def finalize_trace(session_dir: str | Path) -> tuple[Path, Path]:
    """Write redacted outputs, then remove raw data only after full success."""
    session_path = Path(session_dir)
    raw_dir = session_path / "raw"
    events = _read_jsonl(raw_dir / "events.jsonl")
    network = _read_jsonl(raw_dir / "network.jsonl")
    summary = summarize_trace(events, network)
    safe_summary = redact_sensitive(summary)
    timeline_path = session_path / "timeline.json"
    report_path = session_path / "report.md"
    _secure_write_json(timeline_path, safe_summary)
    _secure_write_text(report_path, render_report(safe_summary))
    shutil.rmtree(raw_dir)
    return report_path, timeline_path


class RawTraceWriter:
    """Thread-safe JSONL writer whose contents are deliberately not redacted."""

    def __init__(self, raw_dir: str | Path):
        self.raw_dir = Path(raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.raw_dir, 0o700)
        self._lock = threading.RLock()
        self._closed = False
        self._artifact_index = 0
        self._handles = {
            "events": self._open_jsonl("events.jsonl"),
            "network": self._open_jsonl("network.jsonl"),
            "errors": self._open_jsonl("errors.jsonl"),
        }

    def _open_jsonl(self, filename: str):
        path = self.raw_dir / filename
        fd = _secure_open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        return os.fdopen(fd, "a", encoding="utf-8", buffering=1)

    def _write(self, stream: str, record: Mapping[str, Any]) -> None:
        with self._lock:
            if self._closed:
                return
            handle = self._handles[stream]
            handle.write(json.dumps(dict(record), ensure_ascii=False, default=str) + "\n")
            handle.flush()

    def event(self, category: str, tab_id: str, payload: Mapping[str, Any]) -> None:
        self._write(
            "events",
            {"recorded_at": _now_iso(), "category": category, "tab_id": tab_id, "payload": dict(payload)},
        )

    def network(self, category: str, tab_id: str, payload: Mapping[str, Any]) -> None:
        self._write(
            "network",
            {"recorded_at": _now_iso(), "category": category, "tab_id": tab_id, "payload": dict(payload)},
        )

    def error(self, stage: str, error: BaseException | str) -> None:
        self._write(
            "errors",
            {"recorded_at": _now_iso(), "stage": stage, "error": str(error), "error_type": type(error).__name__},
        )

    def artifact_path(self, category: str, suffix: str) -> Path:
        with self._lock:
            self._artifact_index += 1
            directory = self.raw_dir / category
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
            return directory / f"{self._artifact_index:06d}{suffix}"

    def write_artifact_text(self, category: str, suffix: str, content: str) -> Path:
        path = self.artifact_path(category, suffix)
        _secure_write_text(path, content)
        return path

    def write_artifact_bytes(self, category: str, suffix: str, content: bytes) -> Path:
        path = self.artifact_path(category, suffix)
        _secure_write_bytes(path, content)
        return path

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for handle in self._handles.values():
                try:
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    handle.close()


def create_session_directory(base_dir: str | Path = DEFAULT_OUTPUT_DIR) -> Path:
    base = Path(base_dir).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    session = base / f"trace-{stamp}-{uuid.uuid4().hex[:8]}"
    session.mkdir(mode=0o700)
    os.chmod(session, 0o700)
    return session


def build_browser_options(raw_dir: str | Path):
    """Build a clean headed browser while retaining only the configured proxy."""
    from DrissionPage import ChromiumOptions
    import grok_register_ttk as reg

    options = ChromiumOptions(read_file=False)
    options.headless(False)
    profile_parent = Path(raw_dir) / "DrissionPage"
    profile_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(profile_parent, 0o700)
    options.set_tmp_path(str(profile_parent))
    options.auto_port()
    options.set_argument("--no-first-run")
    options.set_argument("--no-default-browser-check")
    proxy = str((getattr(reg, "config", {}) or {}).get("proxy") or "").strip()
    if proxy:
        try:
            from urllib.parse import urlparse

            parsed = urlparse(proxy if "://" in proxy else f"http://{proxy}")
            if parsed.hostname:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                options.set_proxy(f"{parsed.scheme or 'http'}://{parsed.hostname}:{port}")
        except Exception:
            pass
    return options


_EVENT_CAPTURE_SCRIPT = rf"""
(() => {{
  if (globalThis.__grokManualTraceInstalled) return;
  globalThis.__grokManualTraceInstalled = true;
  const binding = {json.dumps(JS_BINDING_NAME)};
  const trim = (value, limit = 4000) => String(value == null ? '' : value).slice(0, limit);
  const attrs = (element) => {{
    const result = {{}};
    if (!element || !element.attributes) return result;
    for (const attr of element.attributes) result[attr.name] = trim(attr.value, 1000);
    return result;
  }};
  const cssPath = (element) => {{
    if (!element || element.nodeType !== 1) return '';
    const parts = [];
    let current = element;
    while (current && current.nodeType === 1 && parts.length < 8) {{
      let part = current.tagName.toLowerCase();
      if (current.id && !/[0-9a-f]{{12,}}|\d{{6,}}|react|radix|headlessui/i.test(current.id)) {{
        parts.unshift(part + '#' + CSS.escape(current.id));
        break;
      }}
      const parent = current.parentElement;
      if (parent) {{
        const siblings = Array.from(parent.children).filter((node) => node.tagName === current.tagName);
        if (siblings.length > 1) part += `:nth-of-type(${{siblings.indexOf(current) + 1}})`;
      }}
      parts.unshift(part);
      current = parent;
    }}
    return parts.join(' > ');
  }};
  const describe = (element) => {{
    if (!element || element.nodeType !== 1) return {{}};
    return {{
      tag: (element.tagName || '').toLowerCase(),
      id: element.id || '',
      name: element.name || '',
      type: element.type || '',
      role: element.getAttribute('role') || '',
      ariaLabel: element.getAttribute('aria-label') || '',
      autocomplete: element.getAttribute('autocomplete') || '',
      placeholder: element.getAttribute('placeholder') || '',
      text: trim(element.innerText || element.textContent || '', 1000),
      value: 'value' in element ? trim(element.value, 8000) : '',
      checked: 'checked' in element ? Boolean(element.checked) : undefined,
      href: element.href || '',
      action: element.action || '',
      attributes: attrs(element),
      cssPath: cssPath(element),
      outerHTML: trim(element.outerHTML || '', 8000),
      rect: (() => {{
        const rect = element.getBoundingClientRect();
        return {{x: rect.x, y: rect.y, width: rect.width, height: rect.height}};
      }})()
    }};
  }};
  const emit = (type, event, extra = {{}}) => {{
    try {{
      const send = globalThis[binding];
      if (typeof send !== 'function') return;
      send(JSON.stringify({{
        type,
        timestamp: Date.now(),
        performanceMs: performance.now(),
        url: location.href,
        title: document.title,
        viewport: {{width: innerWidth, height: innerHeight, scrollX, scrollY}},
        target: describe(event && event.target),
        ...extra
      }}));
    }} catch (_) {{}}
  }};
  for (const type of ['click', 'dblclick', 'focusin', 'input', 'change', 'submit']) {{
    document.addEventListener(type, (event) => emit(type === 'focusin' ? 'focus' : type, event, {{
      isTrusted: event.isTrusted,
      submitter: type === 'submit' ? describe(event.submitter) : undefined
    }}), true);
  }}
  for (const type of ['keydown', 'keyup']) {{
    document.addEventListener(type, (event) => emit(type, event, {{
      key: event.key,
      code: event.code,
      repeat: event.repeat,
      altKey: event.altKey,
      ctrlKey: event.ctrlKey,
      metaKey: event.metaKey,
      shiftKey: event.shiftKey,
      isTrusted: event.isTrusted
    }}), true);
  }}
  let lastPointer = 0;
  document.addEventListener('pointermove', (event) => {{
    const now = Date.now();
    if (now - lastPointer < 100) return;
    lastPointer = now;
    emit('pointermove', event, {{x: event.clientX, y: event.clientY, pointerType: event.pointerType}});
  }}, true);
  let scrollTimer = 0;
  addEventListener('scroll', (event) => {{
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => emit('scroll', event, {{scrollX, scrollY}}), 150);
  }}, true);
  addEventListener('pageshow', (event) => emit('pageshow', event, {{persisted: event.persisted}}), true);
  addEventListener('beforeunload', (event) => emit('beforeunload', event), true);
  addEventListener('hashchange', (event) => emit('hashchange', event, {{oldURL: event.oldURL, newURL: event.newURL}}), true);
  addEventListener('popstate', (event) => emit('popstate', event, {{state: event.state}}), true);
  emit('trace-installed', null);
}})();
"""

_STORAGE_SCRIPT = """
(() => {
  const objectFromStorage = (storage) => {
    const result = {};
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      result[key] = storage.getItem(key);
    }
    return result;
  };
  return {
    url: location.href,
    cookie: document.cookie,
    localStorage: objectFromStorage(localStorage),
    sessionStorage: objectFromStorage(sessionStorage)
  };
})()
"""


class ManualRegistrationRecorder:
    """CDP-backed recorder for a single, explicitly user-driven session."""

    def __init__(self, session_dir: str | Path, url: str = DEFAULT_SIGNUP_URL):
        self.session_dir = Path(session_dir)
        self.raw_dir = self.session_dir / "raw"
        self.url = url
        self.writer = RawTraceWriter(self.raw_dir)
        self.browser = None
        self._tabs: dict[str, Any] = {}
        self._snapshot_queue: queue.SimpleQueue[tuple[str, str]] = queue.SimpleQueue()
        self._storage_hashes: dict[str, str] = {}
        self._cookie_hash = ""

    def _install_callbacks(self, tab: Any, tab_id: str) -> None:
        driver = tab.driver

        def binding_called(name: str, payload: str, **_kwargs: Any) -> None:
            if name != JS_BINDING_NAME:
                return
            try:
                decoded = json.loads(payload)
                if not isinstance(decoded, dict):
                    decoded = {"type": "binding", "payload": decoded}
            except (json.JSONDecodeError, TypeError):
                decoded = {"type": "binding", "payload": payload}
            self.writer.event("user", tab_id, decoded)
            if decoded.get("type") in {"click", "change", "submit"}:
                self._snapshot_queue.put((tab_id, str(decoded.get("type"))))

        def network_event(category: str):
            return lambda **payload: self.writer.network(category, tab_id, payload)

        def request_will_be_sent(requestId: str, request: Mapping[str, Any], **payload: Any) -> None:
            request_payload = {"requestId": requestId, "request": dict(request), **payload}
            self.writer.network("request", tab_id, request_payload)
            if request.get("hasPostData") and "postData" not in request:
                try:
                    body = tab.run_cdp("Network.getRequestPostData", requestId=requestId)
                    self.writer.network("request_body", tab_id, {"requestId": requestId, **body})
                except BaseException as exc:  # noqa: BLE001
                    self.writer.network(
                        "request_body_error",
                        tab_id,
                        {"requestId": requestId, "error": str(exc), "error_type": type(exc).__name__},
                    )

        def loading_finished(requestId: str, **payload: Any) -> None:
            complete_payload = {"requestId": requestId, **payload}
            self.writer.network("loading_finished", tab_id, complete_payload)
            try:
                body = tab.run_cdp("Network.getResponseBody", requestId=requestId)
                self.writer.network("response_body", tab_id, {"requestId": requestId, **body})
            except BaseException as exc:  # noqa: BLE001 - raw diagnostic must preserve CDP errors
                self.writer.network(
                    "response_body_error",
                    tab_id,
                    {"requestId": requestId, "error": str(exc), "error_type": type(exc).__name__},
                )

        def frame_navigated(frame: Mapping[str, Any], **payload: Any) -> None:
            self.writer.event("navigation", tab_id, {"type": "frame-navigated", "frame": dict(frame), **payload})
            self._snapshot_queue.put((tab_id, "navigation"))

        callbacks = {
            "Runtime.bindingCalled": binding_called,
            "Network.requestWillBeSent": request_will_be_sent,
            "Network.requestWillBeSentExtraInfo": network_event("request_extra"),
            "Network.responseReceived": network_event("response"),
            "Network.responseReceivedExtraInfo": network_event("response_extra"),
            "Network.loadingFailed": network_event("loading_failed"),
            "Network.webSocketCreated": network_event("websocket_created"),
            "Network.webSocketWillSendHandshakeRequest": network_event("websocket_request"),
            "Network.webSocketHandshakeResponseReceived": network_event("websocket_response"),
            "Network.webSocketFrameSent": network_event("websocket_frame_sent"),
            "Network.webSocketFrameReceived": network_event("websocket_frame_received"),
            "Page.frameNavigated": frame_navigated,
            "Page.domContentEventFired": network_event("dom_content_loaded"),
            "Page.loadEventFired": network_event("page_loaded"),
        }
        for event_name, callback in callbacks.items():
            driver.set_callback(event_name, callback)
        driver.set_callback("Network.loadingFinished", loading_finished)

    def attach_tab(self, tab: Any) -> str:
        tab_id = str(getattr(tab, "tab_id", "") or id(tab))
        if tab_id in self._tabs:
            return tab_id
        self._install_callbacks(tab, tab_id)
        tab.run_cdp("Runtime.enable")
        tab.run_cdp("Page.enable")
        tab.run_cdp(
            "Network.enable",
            maxTotalBufferSize=100 * 1024 * 1024,
            maxResourceBufferSize=20 * 1024 * 1024,
            maxPostDataSize=20 * 1024 * 1024,
        )
        tab.run_cdp("Runtime.addBinding", name=JS_BINDING_NAME)
        tab.add_init_js(_EVENT_CAPTURE_SCRIPT)
        tab.run_cdp("Runtime.evaluate", expression=_EVENT_CAPTURE_SCRIPT, awaitPromise=False)
        self._tabs[tab_id] = tab
        self.writer.event("recorder", tab_id, {"type": "tab-attached"})
        return tab_id

    def _attach_new_tabs(self) -> None:
        if self.browser is None:
            return
        try:
            tab_ids = list(self.browser.tab_ids)
        except BaseException as exc:  # noqa: BLE001
            self.writer.error("list-tabs", exc)
            return
        for tab_id in tab_ids:
            key = str(tab_id)
            if key in self._tabs:
                continue
            try:
                self.attach_tab(self.browser.get_tab(tab_id))
            except BaseException as exc:  # noqa: BLE001
                self.writer.error("attach-tab", exc)

    def _capture_snapshot(self, tab_id: str, reason: str) -> None:
        tab = self._tabs.get(tab_id)
        if tab is None:
            return
        try:
            result = tab.run_cdp(
                "Runtime.evaluate",
                expression="document.documentElement ? document.documentElement.outerHTML : ''",
                returnByValue=True,
            )
            html = (((result or {}).get("result") or {}).get("value") or "")
            if html:
                path = self.writer.write_artifact_text("dom", ".html", str(html))
                self.writer.event("snapshot", tab_id, {"type": "dom", "reason": reason, "path": str(path.relative_to(self.raw_dir))})
        except BaseException as exc:  # noqa: BLE001
            self.writer.error("dom-snapshot", exc)
        try:
            result = tab.run_cdp("Page.captureScreenshot", format="png", _timeout=5)
            encoded = ((result or {}).get("data") or "")
            if encoded:
                path = self.writer.write_artifact_bytes(
                    "screenshots", ".png", base64.b64decode(encoded)
                )
                self.writer.event(
                    "snapshot",
                    tab_id,
                    {"type": "screenshot", "reason": reason, "path": str(path.relative_to(self.raw_dir))},
                )
        except BaseException as exc:  # noqa: BLE001
            self.writer.error("screenshot", exc)

    def _drain_snapshots(self, maximum: int = 3) -> None:
        for _ in range(maximum):
            try:
                tab_id, reason = self._snapshot_queue.get_nowait()
            except queue.Empty:
                return
            self._capture_snapshot(tab_id, reason)

    def _capture_sensitive_state(self) -> None:
        cookies = []
        for tab in list(self._tabs.values()):
            try:
                cookies.extend(list(tab.cookies(all_domains=True, all_info=True) or []))
            except BaseException:
                continue
        if cookies:
            digest = hashlib.sha256(json.dumps(cookies, sort_keys=True, default=str).encode()).hexdigest()
            if digest != self._cookie_hash:
                self._cookie_hash = digest
                self.writer.network("cookie_snapshot", "browser", {"cookies": cookies})
        for tab_id, tab in list(self._tabs.items()):
            try:
                result = tab.run_cdp(
                    "Runtime.evaluate", expression=_STORAGE_SCRIPT, returnByValue=True, awaitPromise=False
                )
                value = (((result or {}).get("result") or {}).get("value") or {})
                digest = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
                if digest != self._storage_hashes.get(tab_id):
                    self._storage_hashes[tab_id] = digest
                    self.writer.network("storage_snapshot", tab_id, value)
            except BaseException:
                # Closed/navigating tabs commonly reject Runtime.evaluate; the
                # raw network stream already records the corresponding state.
                continue

    def _browser_alive(self) -> bool:
        try:
            return bool(self.browser and self.browser.states.is_alive)
        except BaseException:
            return False

    def record(self) -> None:
        """Launch the headed browser and block until the user closes it."""
        from DrissionPage import Chromium

        options = build_browser_options(self.raw_dir)
        _secure_write_json(
            self.raw_dir / "meta.json",
            {"started_at": _now_iso(), "url": self.url, "profile_root": str(self.raw_dir / "DrissionPage")},
        )
        try:
            self.browser = Chromium(options)
            initial_tab = self.browser.latest_tab
            self.attach_tab(initial_tab)
            try:
                initial_tab.get(self.url)
            except BaseException as exc:  # noqa: BLE001
                self.writer.error("initial-navigation", exc)
            next_state_capture = 0.0
            while self._browser_alive():
                self._attach_new_tabs()
                self._drain_snapshots()
                now = time.monotonic()
                if now >= next_state_capture:
                    self._capture_sensitive_state()
                    next_state_capture = now + 1.0
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.writer.event("recorder", "browser", {"type": "keyboard-interrupt"})
            raise
        finally:
            if self._browser_alive():
                try:
                    self.browser.quit(timeout=5, force=True, del_data=False)
                except BaseException as exc:  # noqa: BLE001
                    self.writer.error("browser-quit", exc)
                    try:
                        from browser_lifecycle import close_owned_browser

                        close_owned_browser(self.browser)
                    except BaseException as close_exc:  # noqa: BLE001
                        self.writer.error("browser-force-close", close_exc)
            self._drain_snapshots(maximum=20)

    def close(self) -> None:
        self.writer.close()
        _harden_tree_permissions(self.raw_dir)


def _harden_tree_permissions(root: str | Path) -> None:
    path = Path(root)
    if not path.exists():
        return
    for current_root, directories, files in os.walk(path):
        try:
            os.chmod(current_root, 0o700)
        except FileNotFoundError:
            continue
        for directory in directories:
            try:
                os.chmod(Path(current_root) / directory, 0o700)
            except FileNotFoundError:
                pass
        for filename in files:
            try:
                os.chmod(Path(current_root) / filename, 0o600)
            except FileNotFoundError:
                pass


def run_manual_trace(
    *,
    url: str = DEFAULT_SIGNUP_URL,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> tuple[Path, Path]:
    session_dir = create_session_directory(output_dir)
    recorder = ManualRegistrationRecorder(session_dir, url=url)
    try:
        recorder.record()
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001
        raise TraceRunError(session_dir, "recording") from exc
    finally:
        recorder.close()
    try:
        return finalize_trace(session_dir)
    except BaseException as exc:  # noqa: BLE001
        raise TraceRunError(session_dir, "reporting") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="录制一次手动 Grok 注册并生成脱敏分析报告")
    parser.add_argument("--url", default=DEFAULT_SIGNUP_URL, help="要打开的注册入口（不会输出到终端）")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="录制报告目录")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    print("即将打开独立的有头 Chromium。请手动完成一次注册，完成后直接关闭整个浏览器。", flush=True)
    try:
        report_path, timeline_path = run_manual_trace(url=args.url, output_dir=args.output_dir)
    except TraceRunError as exc:
        location = json.dumps(str(exc.session_dir), ensure_ascii=False)
        print(f"录制或报告生成失败；原始数据已保留：{location}", flush=True)
        return 1
    except BaseException as exc:  # noqa: BLE001
        if isinstance(exc, KeyboardInterrupt):
            print("录制已中止；原始数据已保留在输出目录中。", flush=True)
            return 130
        print("录制或报告生成失败；原始数据已保留在输出目录中，请检查其中的 errors.jsonl。", flush=True)
        return 1
    print(f"脱敏报告已生成：{report_path}", flush=True)
    print(f"脱敏时间线已生成：{timeline_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
