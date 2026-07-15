"""Safe-by-construction tracing for automated GUI registration batches.

The tracer records page transitions, DOM actions, page-state summaries and
network metadata.  It deliberately never persists request/response bodies,
headers, cookies, storage values or form values.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from manual_registration_trace import (
    JS_BINDING_NAME,
    _EVENT_CAPTURE_SCRIPT,
    _now_iso,
    _read_jsonl,
    _secure_open,
    _secure_write_json,
    _secure_write_text,
    redact_sensitive,
    redact_text,
    redact_url,
    stable_selector,
    summarize_trace,
)


DEFAULT_OUTPUT_DIR = "manual_registration_traces"
_ACTIVE_BATCH: "AutomaticRegistrationTraceBatch | None" = None
_ACTIVE_BATCH_LOCK = threading.RLock()


def _sanitize_structured(value: Any) -> Any:
    """Remove contextual form values before the generic text redactor runs."""
    if isinstance(value, Mapping):
        result = {str(key): _sanitize_structured(item) for key, item in value.items()}
        tag = str(result.get("tag") or "").lower()
        input_type = str(result.get("type") or "").lower()
        name = str(result.get("name") or "").lower()
        autocomplete = str(result.get("autocomplete") or "").lower()
        sensitive_control = (
            tag in {"input", "textarea", "select"}
            or input_type in {"password", "email", "tel"}
            or any(part in name for part in ("email", "pass", "code", "otp", "token"))
            or any(part in autocomplete for part in ("email", "password", "one-time-code"))
        )
        if sensitive_control:
            for key in ("text", "value", "outerHTML", "outerhtml"):
                if key in result and result[key]:
                    result[key] = "<redacted:input>"
        return result
    if isinstance(value, list):
        return [_sanitize_structured(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_structured(item) for item in value]
    return value


def _candidate_hash(salt: bytes, email: str) -> str:
    digest = hashlib.sha256(salt + email.strip().lower().encode()).hexdigest()[:16]
    return "h-" + "-".join(digest[index : index + 4] for index in range(0, len(digest), 4))


class SafeJsonlWriter:
    """Thread-safe JSONL writer for already-redacted records."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self._lock = threading.RLock()
        self._closed = False
        self._handles = {
            "events": self._open("events.jsonl"),
            "network": self._open("network.jsonl"),
            "pages": self._open("page_states.jsonl"),
            "errors": self._open("errors.jsonl"),
        }

    def _open(self, name: str):
        fd = _secure_open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        return os.fdopen(fd, "a", encoding="utf-8", buffering=1)

    def write(self, stream: str, record: Mapping[str, Any]) -> None:
        safe = redact_sensitive(_sanitize_structured(dict(record)))
        with self._lock:
            if self._closed:
                return
            self._handles[stream].write(json.dumps(safe, ensure_ascii=False, default=str) + "\n")

    def event(self, category: str, tab_id: str, payload: Mapping[str, Any], *, phase: str = "registration") -> None:
        self.write(
            "events",
            {
                "recorded_at": _now_iso(),
                "category": category,
                "tab_id": tab_id,
                "phase": phase,
                "payload": dict(payload),
            },
        )

    def network(self, category: str, tab_id: str, payload: Mapping[str, Any], *, phase: str = "registration") -> None:
        self.write(
            "network",
            {
                "recorded_at": _now_iso(),
                "category": category,
                "tab_id": tab_id,
                "phase": phase,
                "payload": dict(payload),
            },
        )

    def page(self, tab_id: str, payload: Mapping[str, Any], *, phase: str = "registration") -> None:
        self.write(
            "pages",
            {
                "recorded_at": _now_iso(),
                "category": "page_state",
                "tab_id": tab_id,
                "phase": phase,
                "payload": dict(payload),
            },
        )

    def error(self, stage: str, error: BaseException | str) -> None:
        self.write(
            "errors",
            {
                "recorded_at": _now_iso(),
                "stage": stage,
                "error": redact_text(str(error)),
                "error_type": type(error).__name__,
            },
        )

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


def _safe_health(result: Mapping[str, Any] | None) -> dict[str, Any]:
    health = (result or {}).get("health") if isinstance(result, Mapping) else None
    if not isinstance(health, Mapping):
        return {}
    attempts = []
    for item in health.get("attempts") or []:
        if not isinstance(item, Mapping):
            continue
        attempts.append(
            {
                "attempt": item.get("attempt"),
                "offset_sec": item.get("offset_sec"),
                "classification": item.get("classification"),
                "confidence": item.get("confidence"),
                "model": item.get("model"),
                "models_status": item.get("models_status"),
                "responses_status": item.get("http_status"),
                "responses_code": item.get("error_code"),
                "responses_duration_ms": item.get("responses_duration_ms"),
                "fallback_status": item.get("fallback_status"),
                "fallback_code": item.get("fallback_error_code"),
                "fallback_duration_ms": item.get("fallback_duration_ms"),
            }
        )
    return {
        "classification": health.get("classification"),
        "confidence": health.get("confidence"),
        "reject_candidate": bool(health.get("reject_candidate")),
        "reject_reason": health.get("reject_reason"),
        "reason": redact_text(str(health.get("reason") or "")),
        "attempts": attempts,
    }


class AttemptTrace:
    def __init__(
        self,
        batch: "AutomaticRegistrationTraceBatch",
        *,
        worker_id: int,
        idx: int,
        slot: int,
        replacement: int,
    ):
        self.batch = batch
        suffix = uuid.uuid4().hex[:6]
        self.attempt_id = f"w{worker_id}-slot{slot}-idx{idx}-r{replacement}-{suffix}"
        self.directory = batch.session_dir / "attempts" / self.attempt_id
        self.writer = SafeJsonlWriter(self.directory)
        self.metadata: dict[str, Any] = {
            "attempt_id": self.attempt_id,
            "worker_id": worker_id,
            "idx": idx,
            "slot": slot,
            "replacement": replacement,
            "started_at": _now_iso(),
            "candidate_hash": "",
            "outcome": "running",
            "health": {},
        }
        self._lock = threading.RLock()
        self._browsers: dict[int, tuple[Any, str]] = {}
        self._tabs: dict[str, tuple[Any, str]] = {}
        self._page_hashes: dict[str, str] = {}
        self._finished = False
        self.marker("attempt_started", {key: self.metadata[key] for key in ("worker_id", "idx", "slot", "replacement")})

    def marker(self, event_type: str, payload: Mapping[str, Any] | None = None) -> None:
        self.writer.event(
            "automation",
            "worker",
            {"type": event_type, **dict(payload or {})},
            phase="registration",
        )

    def log(self, message: str) -> None:
        self.marker("log", {"message": redact_text(message)})

    def bind_identity(self, email: str) -> None:
        digest = _candidate_hash(self.batch.salt, email)
        self.metadata["candidate_hash"] = digest
        self.marker("identity_bound", {"candidate_hash": digest})

    def record_health(self, result: Mapping[str, Any] | None) -> None:
        health = _safe_health(result)
        self.metadata["health"] = health
        self.writer.event("health", "protocol", {"type": "health_result", **health}, phase="health")

    def attach_browser(self, browser: Any, tab: Any | None = None, *, phase: str = "registration") -> None:
        with self._lock:
            if self._finished:
                return
            self._browsers[id(browser)] = (browser, phase)
        self.marker("browser_attached", {"phase": phase})
        if tab is not None:
            self.attach_tab(tab, browser=browser, phase=phase)

    def detach_browser(self, browser: Any) -> None:
        browser_id = id(browser)
        with self._lock:
            entry = self._browsers.get(browser_id)
        if entry:
            _browser, phase = entry
            self.marker("browser_releasing", {"phase": phase})
        with self._lock:
            self._browsers.pop(browser_id, None)

    def _tab_key(self, browser: Any, tab: Any) -> str:
        tab_id = str(getattr(tab, "tab_id", "") or id(tab))
        return f"{id(browser)}:{tab_id}"

    def attach_tab(self, tab: Any, *, browser: Any, phase: str) -> str:
        key = self._tab_key(browser, tab)
        with self._lock:
            if self._finished or key in self._tabs:
                return key
            self._tabs[key] = (tab, phase)
        try:
            self._install_callbacks(tab, key, phase)
            tab.run_cdp("Runtime.enable")
            tab.run_cdp("Page.enable")
            tab.run_cdp("Network.enable", maxPostDataSize=0)
            tab.run_cdp("Runtime.addBinding", name=JS_BINDING_NAME)
            tab.add_init_js(_EVENT_CAPTURE_SCRIPT)
            tab.run_cdp("Runtime.evaluate", expression=_EVENT_CAPTURE_SCRIPT, awaitPromise=False)
            self.writer.event("recorder", key, {"type": "tab_attached"}, phase=phase)
            self.writer.page(
                key,
                {"reason": "tab_attached", "url": "", "title": "", "readyState": "unknown"},
                phase=phase,
            )
        except BaseException as exc:  # noqa: BLE001
            self.writer.error("attach_tab", exc)
        return key

    def _install_callbacks(self, tab: Any, tab_key: str, phase: str) -> None:
        driver = tab.driver

        def binding_called(name: str, payload: str, **_kwargs: Any) -> None:
            if name != JS_BINDING_NAME:
                return
            try:
                decoded = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                decoded = {"type": "binding"}
            if not isinstance(decoded, Mapping):
                decoded = {"type": "binding"}
            safe = redact_sensitive(dict(decoded))
            target = decoded.get("target") if isinstance(decoded.get("target"), Mapping) else None
            selector = stable_selector(target)
            if selector:
                safe["selector"] = redact_text(selector)
            self.writer.event("user", tab_key, safe, phase=phase)
            page_state = {
                "reason": str(decoded.get("type") or "event"),
                "url": safe.get("url") or "",
                "title": safe.get("title") or "",
                "readyState": "event",
                "viewport": safe.get("viewport") or {},
                "controls": [safe.get("target")] if safe.get("target") else [],
            }
            self._write_page_state(tab_key, page_state, phase=phase)

        def request_will_be_sent(requestId: str, request: Mapping[str, Any], **payload: Any) -> None:
            safe_request = {
                "method": request.get("method"),
                "url": redact_url(str(request.get("url") or "")),
                "hasPostData": bool(request.get("hasPostData")),
            }
            self.writer.network(
                "request",
                tab_key,
                {
                    "requestId": requestId,
                    "timestamp": payload.get("timestamp"),
                    "type": payload.get("type"),
                    "request": safe_request,
                },
                phase=phase,
            )

        def response_received(requestId: str, response: Mapping[str, Any], **payload: Any) -> None:
            self.writer.network(
                "response",
                tab_key,
                {
                    "requestId": requestId,
                    "timestamp": payload.get("timestamp"),
                    "type": payload.get("type"),
                    "response": {
                        "url": redact_url(str(response.get("url") or "")),
                        "status": response.get("status"),
                        "mimeType": response.get("mimeType"),
                        "protocol": response.get("protocol"),
                        "fromDiskCache": response.get("fromDiskCache"),
                        "fromServiceWorker": response.get("fromServiceWorker"),
                    },
                },
                phase=phase,
            )

        def frame_navigated(frame: Mapping[str, Any], **_payload: Any) -> None:
            self.writer.event(
                "navigation",
                tab_key,
                {
                    "type": "frame_navigated",
                    "url": redact_url(str(frame.get("url") or "")),
                    "name": redact_text(str(frame.get("name") or "")),
                    "parentId": frame.get("parentId"),
                },
                phase=phase,
            )
            self._write_page_state(
                tab_key,
                {
                    "reason": "navigation",
                    "url": redact_url(str(frame.get("url") or "")),
                    "title": "",
                    "readyState": "navigating",
                },
                phase=phase,
            )

        def loading_failed(requestId: str, **payload: Any) -> None:
            self.writer.network(
                "loading_failed",
                tab_key,
                {
                    "requestId": requestId,
                    "timestamp": payload.get("timestamp"),
                    "type": payload.get("type"),
                    "errorText": redact_text(str(payload.get("errorText") or "")),
                    "blockedReason": payload.get("blockedReason"),
                    "canceled": payload.get("canceled"),
                },
                phase=phase,
            )

        driver.set_callback("Runtime.bindingCalled", binding_called)
        driver.set_callback("Network.requestWillBeSent", request_will_be_sent)
        driver.set_callback("Network.responseReceived", response_received)
        driver.set_callback("Network.loadingFailed", loading_failed)
        driver.set_callback("Page.frameNavigated", frame_navigated)
        driver.set_callback(
            "Page.domContentEventFired",
            lambda **payload: self.writer.network("dom_content_loaded", tab_key, payload, phase=phase),
        )
        driver.set_callback(
            "Page.loadEventFired",
            lambda **payload: self.writer.network("page_loaded", tab_key, payload, phase=phase),
        )

    def _write_page_state(self, tab_key: str, state: Mapping[str, Any], *, phase: str) -> None:
        safe = redact_sensitive(_sanitize_structured(dict(state)))
        digest = hashlib.sha256(json.dumps(safe, sort_keys=True, default=str).encode()).hexdigest()
        with self._lock:
            if self._page_hashes.get(tab_key) == digest:
                return
            self._page_hashes[tab_key] = digest
        self.writer.page(tab_key, safe, phase=phase)

    def scan(self, *, only_browser: int | None = None) -> None:
        with self._lock:
            browsers = list(self._browsers.items())
        for browser_id, (browser, phase) in browsers:
            if only_browser is not None and browser_id != only_browser:
                continue
            try:
                tab_ids = list(browser.tab_ids or [])
            except BaseException:
                continue
            for tab_id in tab_ids:
                try:
                    tab = browser.get_tab(tab_id)
                    self.attach_tab(tab, browser=browser, phase=phase)
                except BaseException as exc:  # noqa: BLE001
                    self.writer.error("scan_tab", exc)

    def finish(self, outcome: str, *, error: str = "") -> dict[str, Any]:
        with self._lock:
            if self._finished:
                return dict(self.metadata)
        self.scan()
        self.metadata["outcome"] = outcome
        self.metadata["finished_at"] = _now_iso()
        self.metadata["error"] = redact_text(error) if error else ""
        self.marker("attempt_finished", {"outcome": outcome, "error": self.metadata["error"]})
        with self._lock:
            self._finished = True
            self._browsers.clear()
        self.writer.close()
        summary = self._write_reports()
        self.metadata["summary"] = summary
        return dict(self.metadata)

    def _write_reports(self) -> dict[str, Any]:
        return _write_attempt_reports(self.directory, self.metadata)


def _write_attempt_reports(directory: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    events = _read_jsonl(directory / "events.jsonl")
    network = _read_jsonl(directory / "network.jsonl")
    pages = _read_jsonl(directory / "page_states.jsonl")
    trace_summary = summarize_trace(events, network)
    page_sequence = []
    for item in pages:
        payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
        page_sequence.append(
            {
                "recorded_at": item.get("recorded_at"),
                "phase": item.get("phase"),
                "reason": payload.get("reason"),
                "url": payload.get("url"),
                "title": payload.get("title"),
                "ready_state": payload.get("readyState"),
                "headings": payload.get("headings") or [],
                "dialogs": payload.get("dialogs") or [],
                "controls": payload.get("controls") or [],
            }
        )
    summary = {
        **trace_summary,
        "page_state_count": len(page_sequence),
        "page_sequence": page_sequence,
    }
    _secure_write_json(directory / "metadata.json", metadata)
    _secure_write_json(directory / "timeline.json", summary)
    _secure_write_text(directory / "report.md", _render_attempt_report(metadata, summary))
    return {
        "duration_seconds": summary.get("duration_seconds", 0),
        "user_event_count": summary.get("user_event_count", 0),
        "navigation_count": summary.get("navigation_count", 0),
        "network_request_count": summary.get("network_request_count", 0),
        "page_state_count": summary.get("page_state_count", 0),
        "response_statuses": summary.get("response_statuses", {}),
    }


class AutomaticRegistrationTraceBatch:
    """Batch-level observer installed into ``TabPool`` for one GUI run."""

    def __init__(self, output_dir: str | Path = DEFAULT_OUTPUT_DIR, *, page_state_interval: float = 1.0):
        base = Path(output_dir).expanduser().resolve()
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(base, 0o700)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.session_dir = base / f"auto-batch-{stamp}-{uuid.uuid4().hex[:8]}"
        self.session_dir.mkdir(mode=0o700)
        os.chmod(self.session_dir, 0o700)
        self.salt = os.urandom(32)
        self.page_state_interval = max(0.5, float(page_state_interval))
        self._local = threading.local()
        self._lock = threading.RLock()
        self._attempts: dict[str, AttemptTrace] = {}
        self._stop = threading.Event()
        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True, name="auto-registration-trace")
        self._monitor.start()
        _secure_write_json(self.session_dir / "batch.json", {"started_at": _now_iso(), "status": "running"})

    def begin_attempt(self, *, worker_id: int, idx: int, slot: int, replacement: int) -> AttemptTrace:
        attempt = AttemptTrace(
            self,
            worker_id=worker_id,
            idx=idx,
            slot=slot,
            replacement=replacement,
        )
        with self._lock:
            self._attempts[attempt.attempt_id] = attempt
        self._local.attempt = attempt
        return attempt

    def current_attempt(self) -> AttemptTrace | None:
        return getattr(self._local, "attempt", None)

    def browser_ready(self, browser: Any, tab: Any) -> None:
        attempt = self.current_attempt()
        if attempt is not None:
            attempt.attach_browser(browser, tab, phase="registration")

    def browser_releasing(self, browser: Any, tab: Any | None = None) -> None:
        attempt = self.current_attempt()
        if attempt is not None:
            attempt.detach_browser(browser)

    def log(self, message: str) -> None:
        attempt = self.current_attempt()
        if attempt is not None:
            attempt.log(message)

    def bind_identity(self, email: str) -> None:
        attempt = self.current_attempt()
        if attempt is not None:
            attempt.bind_identity(email)

    def record_health(self, result: Mapping[str, Any] | None) -> None:
        attempt = self.current_attempt()
        if attempt is not None:
            attempt.record_health(result)

    def finish_attempt(self, outcome: str, *, error: str = "") -> dict[str, Any] | None:
        attempt = self.current_attempt()
        if attempt is None:
            return None
        try:
            return attempt.finish(outcome, error=error)
        finally:
            self._local.attempt = None

    def _monitor_loop(self) -> None:
        while not self._stop.wait(self.page_state_interval):
            with self._lock:
                attempts = list(self._attempts.values())
            for attempt in attempts:
                try:
                    attempt.scan()
                except BaseException as exc:  # noqa: BLE001
                    attempt.writer.error("monitor", exc)

    def finalize(self) -> tuple[Path, Path]:
        self._stop.set()
        self._monitor.join(timeout=5)
        with self._lock:
            attempts = list(self._attempts.values())
        for attempt in attempts:
            if attempt.metadata.get("outcome") == "running":
                attempt.finish("incomplete", error="batch finalized before attempt outcome")
        summaries = [dict(item.metadata) for item in attempts]
        batch_summary = {
            "started_at": json.loads((self.session_dir / "batch.json").read_text(encoding="utf-8")).get("started_at"),
            "finished_at": _now_iso(),
            "status": "complete",
            "attempt_count": len(summaries),
            "outcomes": dict(Counter(str(item.get("outcome") or "unknown") for item in summaries)),
            "health_classifications": dict(
                Counter(str((item.get("health") or {}).get("classification") or "none") for item in summaries)
            ),
            "attempts": summaries,
        }
        summary_path = self.session_dir / "summary.json"
        report_path = self.session_dir / "report.md"
        _secure_write_json(summary_path, batch_summary)
        _secure_write_text(report_path, _render_batch_report(batch_summary))
        _secure_write_json(
            self.session_dir / "batch.json",
            {"started_at": batch_summary["started_at"], "finished_at": batch_summary["finished_at"], "status": "complete"},
        )
        return report_path, summary_path


def set_active_batch(batch: "AutomaticRegistrationTraceBatch | None") -> None:
    global _ACTIVE_BATCH
    with _ACTIVE_BATCH_LOCK:
        _ACTIVE_BATCH = batch


def attach_active_browser(browser: Any, tab: Any, *, phase: str = "cpa") -> None:
    with _ACTIVE_BATCH_LOCK:
        batch = _ACTIVE_BATCH
    if batch is None:
        return
    attempt = batch.current_attempt()
    if attempt is not None:
        attempt.attach_browser(browser, tab, phase=phase)


def release_active_browser(browser: Any, tab: Any | None = None) -> None:
    with _ACTIVE_BATCH_LOCK:
        batch = _ACTIVE_BATCH
    if batch is None:
        return
    attempt = batch.current_attempt()
    if attempt is not None:
        batch.browser_releasing(browser, tab)


def _render_attempt_report(metadata: Mapping[str, Any], summary: Mapping[str, Any]) -> str:
    health = metadata.get("health") if isinstance(metadata.get("health"), Mapping) else {}
    lines = [
        "# 自动注册候选行为记录",
        "",
        f"- 候选：`{metadata.get('candidate_hash') or metadata.get('attempt_id')}`",
        f"- 结果：`{metadata.get('outcome')}`",
        f"- 健康分类：`{health.get('classification') or 'none'}`",
        f"- 页面状态：`{summary.get('page_state_count', 0)}`",
        f"- 页面导航：`{summary.get('navigation_count', 0)}`",
        f"- 用户/自动化 DOM 事件：`{summary.get('user_event_count', 0)}`",
        f"- 网络请求：`{summary.get('network_request_count', 0)}`",
        "",
        "## 页面顺序",
        "",
        "| 时间 | 阶段 | 原因 | 页面 | 标题 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in (summary.get("page_sequence") or [])[:300]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | {} |".format(
                item.get("recorded_at", ""),
                item.get("phase", ""),
                item.get("reason", ""),
                str(item.get("url") or "").replace("|", "\\|"),
                str(item.get("title") or "").replace("|", "\\|"),
            )
        )
    lines.extend(["", "## 健康检查", ""])
    attempts = health.get("attempts") or []
    if attempts:
        lines.extend(["| 次数 | 时间点 | 分类 | 主接口 | 备用接口 |", "| ---: | ---: | --- | --- | --- |"])
        for item in attempts:
            lines.append(
                f"| {item.get('attempt', '')} | {item.get('offset_sec', '')}s | "
                f"`{item.get('classification', '')}` | `{item.get('responses_status', '')}` | "
                f"`{item.get('fallback_status', '')}` |"
            )
    else:
        lines.append("无健康检查记录。")
    lines.extend(
        [
            "",
            "完整脱敏事件保存在 `events.jsonl`、`network.jsonl`、`page_states.jsonl` 和 `timeline.json`。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_batch_report(summary: Mapping[str, Any]) -> str:
    attempts = summary.get("attempts") or []
    lines = [
        "# GUI 自动注册行为对比",
        "",
        f"- 候选总数：`{summary.get('attempt_count', 0)}`",
        f"- 结果分布：`{json.dumps(summary.get('outcomes') or {}, ensure_ascii=False)}`",
        f"- 健康分类：`{json.dumps(summary.get('health_classifications') or {}, ensure_ascii=False)}`",
        "",
        "## 候选结果",
        "",
        "| 候选 | 槽位 | 补号 | 结果 | 健康分类 | 页面状态 | DOM事件 | 网络请求 |",
        "| --- | ---: | ---: | --- | --- | ---: | ---: | ---: |",
    ]
    for item in attempts:
        health = item.get("health") if isinstance(item.get("health"), Mapping) else {}
        stats = item.get("summary") if isinstance(item.get("summary"), Mapping) else {}
        lines.append(
            f"| `{item.get('candidate_hash') or item.get('attempt_id')}` | {item.get('slot', '')} | "
            f"{item.get('replacement', '')} | `{item.get('outcome', '')}` | "
            f"`{health.get('classification') or 'none'}` | {stats.get('page_state_count', 0)} | "
            f"{stats.get('user_event_count', 0)} | {stats.get('network_request_count', 0)} |"
        )
    lines.extend(
        [
            "",
            "## 判定差异",
            "",
            "- 成功候选：健康探测至少一次转为 `healthy`，之后才写入账号账本和 CPA 文件。",
            "- 权限拒绝候选：多次探测持续为确认的 `permission_denied`，不落盘并进入补号。",
            "- 每个候选目录中的页面顺序、DOM 行为和网络状态可用于比较两类账号在健康门之前是否存在差异。",
            "",
        ]
    )
    return "\n".join(lines)


def rebuild_batch_reports(session_dir: str | Path) -> tuple[Path, Path]:
    """Rebuild reports from persisted safe JSONL after a previous report failure."""
    session = Path(session_dir).expanduser().resolve()
    summary_path = session / "summary.json"
    if not summary_path.is_file():
        raise FileNotFoundError(f"batch summary not found: {summary_path}")
    batch_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    attempts = batch_summary.get("attempts") or []
    for item in attempts:
        if not isinstance(item, dict):
            continue
        attempt_id = str(item.get("attempt_id") or "")
        attempt_dir = session / "attempts" / attempt_id
        if not attempt_id or not attempt_dir.is_dir():
            continue
        item["summary"] = _write_attempt_reports(attempt_dir, item)
    batch_summary["attempt_count"] = len(attempts)
    batch_summary["outcomes"] = dict(
        Counter(str(item.get("outcome") or "unknown") for item in attempts if isinstance(item, Mapping))
    )
    batch_summary["health_classifications"] = dict(
        Counter(
            str((item.get("health") or {}).get("classification") or "none")
            for item in attempts
            if isinstance(item, Mapping)
        )
    )
    report_path = session / "report.md"
    _secure_write_json(summary_path, batch_summary)
    _secure_write_text(report_path, _render_batch_report(batch_summary))
    return report_path, summary_path
