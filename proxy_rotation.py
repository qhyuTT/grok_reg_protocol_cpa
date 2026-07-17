#!/usr/bin/env python3
"""Clash Meta egress rotation + per-IP cooldown for registration.

When enabled, each account acquires a process-wide lease:
  select US node in the Clash Selector group → switch → probe egress IP/country
  → hold until register + mint + health finalize → release with cooldown.

Single mixed-port gateways require serial pipelines (register_threads=1,
mint_workers=0) so mint cannot race with the next node switch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen

try:
    import fcntl
except ImportError:  # pragma: no cover - supported runtime is macOS/Linux
    fcntl = None  # type: ignore[assignment]

LogFn = Callable[[str], None]

_ROOT = Path(__file__).resolve().parent
_DEFAULT_STATE = _ROOT / "cpa_auths" / "proxy_egress_state.json"

_NESTED_GROUP_NAMES = frozenset({"自动选择", "故障转移", "DIRECT", "REJECT", "GLOBAL"})

_manager_lock = threading.Lock()
_manager: "EgressLeaseManager | None" = None
_manager_sig: tuple | None = None
_thread_local = threading.local()


class EgressUnavailable(RuntimeError):
    """Raised when rotation cannot provide a verified eligible egress."""

    def __init__(self, reason: str):
        self.reason = str(reason or "egress unavailable")
        super().__init__(self.reason)


def _log_default(msg: str) -> None:
    print(msg, flush=True)


def _bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off", ""}:
        return False
    return default


def _float(v: Any, default: float) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _list_str(v: Any, default: list[str]) -> list[str]:
    if v is None:
        return list(default)
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
        return parts or list(default)
    if isinstance(v, (list, tuple)):
        out = [str(x).strip() for x in v if str(x).strip()]
        return out or list(default)
    return list(default)


def _compile_re(pattern: str, flags: int = re.I) -> re.Pattern[str] | None:
    p = (pattern or "").strip()
    if not p:
        return None
    try:
        return re.compile(p, flags)
    except re.error:
        return re.compile(re.escape(p), flags)


def resolve_gateway(config: dict[str, Any]) -> str:
    explicit = str(config.get("proxy_rotation_gateway") or "").strip()
    if explicit:
        return explicit
    return str(config.get("cpa_proxy") or config.get("proxy") or "").strip()


def _proxy_endpoint(value: Any, label: str) -> tuple[str, str, int]:
    raw = str(value or "").strip()
    if not raw:
        raise EgressUnavailable(f"proxy rotation config invalid: {label} is empty")
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError as exc:
        raise EgressUnavailable(
            f"proxy rotation config invalid: {label} has invalid port"
        ) from exc
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https", "socks5", "socks5h"} or not host or port is None:
        raise EgressUnavailable(
            f"proxy rotation config invalid: {label} must be a proxy URL with host and port"
        )
    if not 1 <= port <= 65535:
        raise EgressUnavailable(f"proxy rotation config invalid: {label} port is out of range")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise EgressUnavailable(
            f"proxy rotation config invalid: {label} must not contain path/query/fragment"
        )
    return scheme, host, port


def validate_rotation_config(config: dict[str, Any] | None) -> None:
    """Validate that all traffic uses the same usable Clash mixed-port."""
    cfg = dict(config or {})
    if not rotation_enabled(cfg):
        return
    effective_cpa_proxy = cfg.get("cpa_proxy") or cfg.get("proxy")
    endpoints = {
        "proxy": _proxy_endpoint(cfg.get("proxy"), "proxy"),
        "cpa_proxy": _proxy_endpoint(effective_cpa_proxy, "cpa_proxy or proxy"),
        "proxy_rotation_gateway": _proxy_endpoint(
            resolve_gateway(cfg), "proxy_rotation_gateway"
        ),
    }
    identities = {(host, port) for _scheme, host, port in endpoints.values()}
    if len(identities) != 1:
        rendered = ", ".join(
            f"{name}={host}:{port}" for name, (_scheme, host, port) in endpoints.items()
        )
        raise EgressUnavailable(
            f"proxy rotation config invalid: proxy endpoints must share one mixed-port ({rendered})"
        )


def rotation_enabled(config: dict[str, Any] | None) -> bool:
    return _bool((config or {}).get("proxy_rotation_enabled"), False)


def force_serial_pipeline(config: dict[str, Any] | None) -> bool:
    return rotation_enabled(config)


def apply_rotation_concurrency(
    config: dict[str, Any] | None,
    threads: int,
    mint_workers: int,
) -> tuple[int, int, bool]:
    """Return (threads, mint_workers, changed) when rotation forces serial."""
    if not force_serial_pipeline(config):
        return threads, mint_workers, False
    new_t, new_m = 1, 0
    changed = threads != new_t or mint_workers != new_m
    return new_t, new_m, changed


# ── Clash controller ──────────────────────────────────────────────────────────


class ClashController:
    """Minimal Clash Meta external-controller client."""

    def __init__(
        self,
        base_url: str,
        secret: str = "",
        timeout: float = 5.0,
        log: LogFn | None = None,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.secret = (secret or "").strip()
        self.timeout = max(0.5, float(timeout))
        self.log = log or _log_default

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.secret:
            h["Authorization"] = f"Bearer {self.secret}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> tuple[int, Any]:
        if not self.base_url:
            return 0, {"error": "empty controller url"}
        url = f"{self.base_url}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = Request(url, data=data, headers=self._headers(), method=method.upper())
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                code = getattr(resp, "status", None) or resp.getcode() or 200
                if not raw:
                    return int(code), {}
                try:
                    return int(code), json.loads(raw.decode("utf-8"))
                except Exception:
                    return int(code), {"raw": raw.decode("utf-8", errors="replace")}
        except HTTPError as exc:
            raw = b""
            try:
                raw = exc.read() or b""
            except Exception:
                pass
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {"error": str(exc)}
            except Exception:
                payload = {"error": str(exc), "raw": raw.decode("utf-8", errors="replace")}
            return int(exc.code or 0), payload
        except (URLError, TimeoutError, OSError) as exc:
            return 0, {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}

    def version(self) -> dict[str, Any]:
        code, data = self._request("GET", "/version")
        if code and 200 <= code < 300 and isinstance(data, dict):
            return data
        return {}

    def get_group(self, group: str) -> dict[str, Any] | None:
        name = (group or "").strip()
        if not name:
            return None
        code, data = self._request("GET", f"/proxies/{quote(name, safe='')}")
        if code and 200 <= code < 300 and isinstance(data, dict):
            return data
        return None

    def list_group_nodes(self, group: str) -> tuple[str, list[str]]:
        """Return (now, all_names). Empty on failure."""
        info = self.get_group(group)
        if not info:
            return "", []
        now = str(info.get("now") or "")
        all_names = [str(x) for x in (info.get("all") or []) if str(x).strip()]
        return now, all_names

    def switch(self, group: str, node: str) -> bool:
        name = (group or "").strip()
        node_name = (node or "").strip()
        if not name or not node_name:
            return False
        code, data = self._request(
            "PUT",
            f"/proxies/{quote(name, safe='')}",
            body={"name": node_name},
        )
        if code and 200 <= code < 300:
            return True
        # Some builds return 204 with empty body already handled; treat 0 as fail.
        err = data.get("error") if isinstance(data, dict) else data
        self.log(f"[proxy-rot] switch failed group={name!r} node={node_name!r} code={code} err={err}")
        return False


# ── Egress probe ──────────────────────────────────────────────────────────────


def _normalize_country(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    up = s.upper()
    if len(up) == 2:
        return up
    aliases = {
        "UNITED STATES": "US",
        "UNITED STATES OF AMERICA": "US",
        "USA": "US",
        "U.S.": "US",
        "U.S.A.": "US",
    }
    return aliases.get(up, up if len(up) == 2 else "")


def probe_egress(
    gateway: str,
    urls: list[str] | None = None,
    timeout: float = 10.0,
) -> tuple[str, str]:
    """Return (ip, country_code). Empty strings on failure.

    Uses gateway as HTTP(S) proxy. Prefer ``requests`` (handles TLS/proxies
    reliably on macOS); fall back to urllib.
    """
    gw = (gateway or "").strip()
    probe_urls = urls or [
        "https://ipinfo.io/json",
        "https://api.ipify.org?format=json",
        "http://ip-api.com/json/?fields=status,country,countryCode,query",
    ]
    proxies = {"http": gw, "https": gw} if gw else None
    headers = {"Accept": "application/json", "User-Agent": "proxy-rotation/1.0"}
    timeout_s = max(1.0, float(timeout))

    ip = ""
    country = ""

    # Prefer requests — urllib often fails SSL verify via local Clash on macOS.
    try:
        import requests  # type: ignore
    except Exception:
        requests = None  # type: ignore

    for url in probe_urls:
        u = (url or "").strip()
        if not u:
            continue
        raw = ""
        try:
            if requests is not None:
                resp = requests.get(
                    u, proxies=proxies, headers=headers, timeout=timeout_s
                )
                raw = resp.text or ""
                if resp.status_code >= 400:
                    continue
            else:
                handlers = []
                if gw:
                    handlers.append(ProxyHandler({"http": gw, "https": gw}))
                opener = build_opener(*handlers) if handlers else build_opener()
                req = Request(u, headers=headers)
                with opener.open(req, timeout=timeout_s) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
        except Exception:
            continue

        try:
            data = json.loads(raw)
        except Exception:
            text = raw.strip()
            if text and " " not in text and len(text) < 64:
                ip = ip or text
            continue
        if not isinstance(data, dict):
            continue
        cand_ip = data.get("ip") or data.get("query") or data.get("origin") or ""
        if cand_ip:
            ip = str(cand_ip).strip()
        cand_cc = _normalize_country(
            data.get("countryCode") or data.get("country_code") or data.get("country")
        )
        if cand_cc:
            country = cand_cc
        if ip and country:
            return ip, country
    return ip, country


# ── Cooldown store ────────────────────────────────────────────────────────────


class CooldownStore:
    def __init__(self, path: Path, log: LogFn | None = None):
        self.path = Path(path)
        self.log = log or _log_default
        self._lock = threading.RLock()
        self.data: dict[str, Any] = {"version": 1, "by_ip": {}, "by_node": {}, "rr_index": 0}
        self.load()

    def load(self) -> None:
        with self._lock:
            self.data = {"version": 1, "by_ip": {}, "by_node": {}, "rr_index": 0}
            if not self.path.exists():
                return
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.data["by_ip"] = dict(raw.get("by_ip") or {})
                    self.data["by_node"] = dict(raw.get("by_node") or {})
                    self.data["rr_index"] = int(raw.get("rr_index") or 0)
                    self.data["version"] = int(raw.get("version") or 1)
            except Exception as exc:
                self.log(f"[proxy-rot] state load failed, starting empty: {exc}")
                self.data = {"version": 1, "by_ip": {}, "by_node": {}, "rr_index": 0}

    def save(self) -> None:
        with self._lock:
            self.data["updated_at"] = int(time.time())
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(
                f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            )
            payload = json.dumps(self.data, ensure_ascii=False, indent=2)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            finally:
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass

    def ip_record(self, ip: str) -> dict[str, Any]:
        ip = (ip or "").strip()
        with self._lock:
            rec = self.data["by_ip"].get(ip)
            if not isinstance(rec, dict):
                rec = {}
                self.data["by_ip"][ip] = rec
            return rec

    def node_record(self, node: str) -> dict[str, Any]:
        node = (node or "").strip()
        with self._lock:
            rec = self.data["by_node"].get(node)
            if not isinstance(rec, dict):
                rec = {}
                self.data["by_node"][node] = rec
            return rec

    def is_ip_cooling(self, ip: str, now: float | None = None) -> bool:
        if not ip:
            return False
        now = time.time() if now is None else now
        with self._lock:
            rec = self.data["by_ip"].get(ip) or {}
            until = float(rec.get("cooldown_until") or 0)
            return until > now

    def is_node_bad_geo(self, node: str, now: float | None = None) -> bool:
        if not node:
            return False
        now = time.time() if now is None else now
        with self._lock:
            rec = self.data["by_node"].get(node) or {}
            until = float(rec.get("bad_geo_until") or 0)
            return until > now

    def earliest_ip_ready(self, ips: list[str], now: float | None = None) -> float:
        now = time.time() if now is None else now
        best = now
        with self._lock:
            for ip in ips:
                rec = self.data["by_ip"].get(ip) or {}
                until = float(rec.get("cooldown_until") or 0)
                if until > best:
                    # we want the soonest future ready among cooling ips
                    pass
        # Find min cooldown_until among still-cooling IPs; if none, return now
        candidates: list[float] = []
        with self._lock:
            for ip in ips:
                rec = self.data["by_ip"].get(ip) or {}
                until = float(rec.get("cooldown_until") or 0)
                if until > now:
                    candidates.append(until)
        return min(candidates) if candidates else now

    def mark_outcome(
        self,
        *,
        ip: str,
        node: str,
        outcome: str,
        cooldown_sec: float,
        now: float | None = None,
    ) -> float:
        now = time.time() if now is None else now
        until = now + max(0.0, float(cooldown_sec))
        with self._lock:
            if ip:
                rec = self.ip_record(ip)
                rec["node_name"] = node
                rec["last_outcome"] = outcome
                rec["last_used_at"] = now
                rec["cooldown_until"] = until
                if outcome == "healthy":
                    rec["healthy_count"] = int(rec.get("healthy_count") or 0) + 1
                    rec["consecutive_denies"] = 0
                elif outcome == "permission_denied":
                    rec["denied_count"] = int(rec.get("denied_count") or 0) + 1
                    rec["consecutive_denies"] = int(rec.get("consecutive_denies") or 0) + 1
                elif outcome == "egress_access_denied":
                    rec["egress_denied_count"] = int(rec.get("egress_denied_count") or 0) + 1
                    rec["consecutive_denies"] = 0
                else:
                    rec["consecutive_denies"] = 0
            if node:
                nrec = self.node_record(node)
                if ip:
                    nrec["last_egress_ip"] = ip
                nrec["last_used_at"] = now
            self.save()
        return until

    def mark_bad_geo(self, node: str, sec: float, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            nrec = self.node_record(node)
            nrec["bad_geo_until"] = now + max(0.0, float(sec))
            self.save()

    def next_rr_index(self) -> int:
        with self._lock:
            idx = int(self.data.get("rr_index") or 0)
            self.data["rr_index"] = idx + 1
            self.save()
            return idx


# ── Lease ─────────────────────────────────────────────────────────────────────


@dataclass
class EgressLease:
    lease_id: str
    gateway: str
    node_name: str
    egress_ip: str
    country: str
    acquired_at: float
    group: str
    fixed: bool = False  # True only when rotation is disabled.
    released: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "gateway": self.gateway,
            "node_name": self.node_name,
            "egress_ip": self.egress_ip,
            "country": self.country,
            "group": self.group,
            "fixed": self.fixed,
            "acquired_at": self.acquired_at,
        }


# ── Manager ───────────────────────────────────────────────────────────────────


class EgressLeaseManager:
    def __init__(self, config: dict[str, Any], log: LogFn | None = None):
        self.config = dict(config or {})
        self.log = log or _log_default
        self.enabled = rotation_enabled(self.config)
        validate_rotation_config(self.config)
        self.gateway = resolve_gateway(self.config)
        self.controller_url = str(self.config.get("proxy_rotation_controller_url") or "").strip()
        self.secret = str(self.config.get("proxy_rotation_controller_secret") or "").strip()
        self.group = str(self.config.get("proxy_rotation_proxy_group") or "飞鸟云").strip()
        self.include_re = _compile_re(
            str(self.config.get("proxy_rotation_node_filter") or r"(?i)美国")
        )
        self.exclude_re = _compile_re(
            str(
                self.config.get("proxy_rotation_node_exclude")
                or r"(?i)自动选择|故障转移|剩余流量|套餐到期|更新订阅|有超过20|客户端设置|电报|防失联|新加坡|日本|台湾|hy2台湾"
            )
        )
        self.allowed_countries = {
            c.upper() for c in _list_str(self.config.get("proxy_rotation_allowed_countries"), ["US"])
        }
        self.require_us = _bool(self.config.get("proxy_rotation_require_us"), True)
        self.probe_urls = _list_str(
            self.config.get("proxy_rotation_ip_probe_urls"),
            ["https://ipinfo.io/json", "https://api.ipify.org?format=json"],
        )
        self.switch_settle = _float(self.config.get("proxy_rotation_switch_settle_sec"), 1.5)
        self.switch_confirm_timeout = max(
            0.1,
            _float(self.config.get("proxy_rotation_switch_confirm_timeout_sec"), 5.0),
        )
        self.switch_confirm_interval = max(
            0.0,
            _float(self.config.get("proxy_rotation_switch_confirm_interval_sec"), 0.2),
        )
        self.controller_timeout = _float(self.config.get("proxy_rotation_controller_timeout_sec"), 5)
        self.probe_timeout = _float(self.config.get("proxy_rotation_probe_timeout_sec"), 10)
        self.max_switch_attempts = max(1, _int(self.config.get("proxy_rotation_max_switch_attempts"), 8))
        self.max_wait_sec = max(0.0, _float(self.config.get("proxy_rotation_max_wait_sec"), 600))
        self.cd_healthy = _float(self.config.get("proxy_rotation_cooldown_healthy_sec"), 360)
        self.cd_denied = _float(self.config.get("proxy_rotation_cooldown_denied_sec"), 900)
        self.cd_egress_denied = _float(
            self.config.get("proxy_rotation_cooldown_egress_denied_sec"), 1800
        )
        self.cd_forbidden_unknown = _float(
            self.config.get("proxy_rotation_cooldown_forbidden_unknown_sec"), 180
        )
        self.cd_soft = _float(self.config.get("proxy_rotation_cooldown_soft_sec"), 180)
        self.cd_fail = _float(self.config.get("proxy_rotation_cooldown_fail_sec"), 60)
        self.cd_activation = _float(
            self.config.get("proxy_rotation_cooldown_activation_failed_sec"), 120
        )
        self.cd_bad_geo = _float(self.config.get("proxy_rotation_bad_geo_cooldown_sec"), 3600)
        self.egress_denied_breaker_threshold = max(
            1,
            _int(self.config.get("proxy_rotation_egress_denied_breaker_threshold"), 2),
        )

        state_raw = str(self.config.get("proxy_rotation_state_file") or "").strip()
        state_path = Path(state_raw) if state_raw else _DEFAULT_STATE
        if not state_path.is_absolute():
            state_path = (_ROOT / state_path).resolve()
        lock_raw = str(self.config.get("proxy_rotation_lock_file") or "").strip()
        lock_path = Path(lock_raw) if lock_raw else state_path.with_suffix(".lock")
        if not lock_path.is_absolute():
            lock_path = (_ROOT / lock_path).resolve()
        history_raw = str(self.config.get("proxy_rotation_history_file") or "").strip()
        history_path = (
            Path(history_raw)
            if history_raw
            else state_path.parent / "proxy_egress_history.jsonl"
        )
        if not history_path.is_absolute():
            history_path = (_ROOT / history_path).resolve()
        self.lock_path = lock_path
        self.history_path = history_path
        self.store = CooldownStore(state_path, log=self.log)
        self.controller = ClashController(
            self.controller_url,
            secret=self.secret,
            timeout=self.controller_timeout,
            log=self.log,
        )

        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._acquire_guard = threading.Lock()
        self._active: EgressLease | None = None
        self._process_lock_fh: Any | None = None
        self._nodes_cache: list[str] = []
        self._nodes_cache_at = 0.0
        self._node_last_ip: dict[str, str] = {}
        self._consecutive_egress_denied = 0
        self._egress_denied_keys: set[str] = set()

    def force_serial_pipeline(self) -> bool:
        return self.enabled

    def current_lease(self) -> EgressLease | None:
        return getattr(_thread_local, "lease", None)

    def set_thread_lease(self, lease: EgressLease | None) -> None:
        _thread_local.lease = lease

    def current_lease_metadata(self) -> dict[str, Any]:
        lease = self.current_lease() or self._active
        if lease is None:
            return {}
        return lease.describe()

    def describe(self, lease: EgressLease | None) -> dict[str, Any]:
        if lease is None:
            return {}
        return lease.describe()

    def batch_breaker_tripped(self) -> bool:
        with self._lock:
            return self._consecutive_egress_denied >= self.egress_denied_breaker_threshold

    def should_stop_batch(self) -> bool:
        return self.batch_breaker_tripped()

    def reset_batch_breaker(self) -> None:
        with self._lock:
            self._consecutive_egress_denied = 0
            self._egress_denied_keys.clear()

    @staticmethod
    def _ip_hash(ip: str) -> str:
        value = (ip or "").strip()
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12] if value else ""

    def _append_history(
        self,
        event: str,
        lease: EgressLease | None = None,
        *,
        outcome: str = "",
        reason: str = "",
        cooldown_sec: float = 0.0,
    ) -> None:
        row: dict[str, Any] = {
            "timestamp": int(time.time()),
            "event": event,
        }
        if lease is not None:
            row.update(
                {
                    "lease_id": lease.lease_id,
                    "node_name": lease.node_name,
                    "country": lease.country,
                    "group": lease.group,
                    "fixed": lease.fixed,
                    "ip_hash": self._ip_hash(lease.egress_ip),
                    "acquired_at": int(lease.acquired_at),
                }
            )
        if outcome:
            row["outcome"] = outcome
        if reason:
            row["reason"] = reason
        if cooldown_sec:
            row["cooldown_sec"] = int(max(0.0, cooldown_sec))
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            payload = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
            fd = os.open(
                self.history_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(self.history_path, 0o600)
        except Exception as exc:
            self.log(f"[proxy-rot] history append failed: {exc}")

    def _acquire_process_lock(
        self,
        *,
        cancel: Callable[[], bool] | None,
        deadline: float,
    ) -> None:
        if fcntl is None:
            raise EgressUnavailable("cross-process proxy rotation lock is unavailable")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fh = os.fdopen(fd, "a+", encoding="utf-8")
        try:
            os.fchmod(fh.fileno(), 0o600)
            while True:
                if cancel and cancel():
                    raise EgressUnavailable("proxy rotation acquisition cancelled")
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._process_lock_fh = fh
                    return
                except BlockingIOError:
                    if deadline and time.monotonic() >= deadline:
                        raise EgressUnavailable("proxy rotation max wait exhausted")
                    time.sleep(0.1)
        except Exception:
            fh.close()
            raise

    def _release_process_lock(self) -> None:
        fh = self._process_lock_fh
        self._process_lock_fh = None
        if fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()

    def _confirm_selection(
        self,
        node: str,
        *,
        cancel: Callable[[], bool] | None,
    ) -> bool:
        deadline = time.monotonic() + self.switch_confirm_timeout
        consecutive = 0
        while time.monotonic() < deadline:
            if cancel and cancel():
                raise EgressUnavailable("proxy rotation acquisition cancelled")
            info = self.controller.get_group(self.group)
            current = str((info or {}).get("now") or "")
            if current == node:
                consecutive += 1
                if consecutive >= 2:
                    return True
            else:
                consecutive = 0
            if self.switch_confirm_interval > 0:
                time.sleep(self.switch_confirm_interval)
        return False

    def _probe_stable_egress(
        self,
        *,
        cancel: Callable[[], bool] | None,
    ) -> tuple[str, str]:
        """Require two matching IP observations after the selector is confirmed."""
        first_ip, first_country = probe_egress(
            self.gateway, urls=self.probe_urls, timeout=self.probe_timeout
        )
        if not first_ip:
            return "", ""
        if cancel and cancel():
            raise EgressUnavailable("proxy rotation acquisition cancelled")
        if self.switch_confirm_interval > 0:
            time.sleep(self.switch_confirm_interval)
        second_ip, second_country = probe_egress(
            self.gateway, urls=self.probe_urls, timeout=self.probe_timeout
        )
        if not second_ip or second_ip != first_ip:
            return "", ""
        return second_ip, second_country or first_country

    def _filter_nodes(self, names: list[str]) -> list[str]:
        out: list[str] = []
        for n in names:
            if not n or n in _NESTED_GROUP_NAMES:
                continue
            if self.exclude_re and self.exclude_re.search(n):
                continue
            if self.include_re and not self.include_re.search(n):
                continue
            out.append(n)
        return out

    def _refresh_nodes(self, force: bool = False) -> list[str]:
        now = time.time()
        if not force and self._nodes_cache and (now - self._nodes_cache_at) < 60:
            return list(self._nodes_cache)
        _now_name, all_names = self.controller.list_group_nodes(self.group)
        nodes = self._filter_nodes(all_names)
        if nodes:
            self._nodes_cache = nodes
            self._nodes_cache_at = now
        return list(nodes)

    def _cooldown_for_outcome(self, outcome: str) -> float:
        o = (outcome or "").strip().lower()
        if o in {"healthy", "accepted_healthy"}:
            return self.cd_healthy
        if o in {"permission_denied", "denied", "rejected"}:
            return self.cd_denied
        if o in {"egress_access_denied", "egress_denied"}:
            return self.cd_egress_denied
        if o in {"forbidden_unknown", "generic_forbidden", "generic_403"}:
            return self.cd_forbidden_unknown
        if o in {"endpoint_inconsistent"}:
            return self.cd_soft
        if o in {"activation_failed"}:
            return self.cd_activation
        if o in {"soft_keep", "soft", "unknown", "accepted"}:
            return self.cd_soft
        if o in {"cancelled", "cancel"}:
            return 0.0
        if o in {"reg_fail", "failed", "fail"}:
            return self.cd_fail
        return self.cd_fail

    def _static_lease(self, reason: str) -> EgressLease:
        ip, country = "", ""
        if self.gateway:
            try:
                ip, country = probe_egress(
                    self.gateway, urls=self.probe_urls, timeout=self.probe_timeout
                )
            except Exception:
                pass
        lease = EgressLease(
            lease_id=uuid.uuid4().hex[:12],
            gateway=self.gateway,
            node_name="(fixed)",
            egress_ip=ip,
            country=country,
            acquired_at=time.time(),
            group=self.group,
            fixed=True,
            meta={"reason": reason},
        )
        self.log(
            f"[proxy-rot] fixed lease reason={reason} gateway={self.gateway or '(none)'} "
            f"ip={ip or '?'} country={country or '?'}"
        )
        return lease

    def _node_known_cooling(self, node: str, now: float) -> bool:
        if self.store.is_node_bad_geo(node, now):
            return True
        ip = self._node_last_ip.get(node) or (self.store.node_record(node).get("last_egress_ip") or "")
        if ip and self.store.is_ip_cooling(str(ip), now):
            return True
        return False

    def _ordered_candidates(self, nodes: list[str], now: float) -> list[str]:
        ready: list[str] = []
        for n in nodes:
            if self._node_known_cooling(n, now):
                continue
            else:
                ready.append(n)
        if not ready:
            return []
        # RR among ready
        start = self.store.next_rr_index() % len(ready)
        return ready[start:] + ready[:start]

    def acquire(self, *, cancel: Callable[[], bool] | None = None) -> EgressLease:
        """Acquire an exclusive verified egress, held until :meth:`release`."""
        if not self.enabled:
            lease = self._static_lease("rotation_disabled")
            self.set_thread_lease(lease)
            self._append_history("acquire", lease)
            return lease
        deadline = time.monotonic() + self.max_wait_sec if self.max_wait_sec > 0 else 0.0
        with self._acquire_guard:
            with self._condition:
                while self._active is not None and not self._active.released:
                    if cancel and cancel():
                        raise EgressUnavailable("proxy rotation acquisition cancelled")
                    if deadline and time.monotonic() >= deadline:
                        raise EgressUnavailable("proxy rotation max wait exhausted")
                    self._condition.wait(timeout=0.1)

            self._acquire_process_lock(cancel=cancel, deadline=deadline)
            try:
                # Another process may have updated cooldowns while this process waited.
                self.store.load()
                with self._condition:
                    lease = self._try_select_and_switch(cancel=cancel, deadline=deadline)
                    self._active = lease
                    self.set_thread_lease(lease)
                    self._append_history("acquire", lease)
                    return lease
            except EgressUnavailable as exc:
                self._append_history("acquire_failed", reason=exc.reason)
                self._release_process_lock()
                raise
            except Exception as exc:
                self._append_history("acquire_failed", reason=type(exc).__name__)
                self._release_process_lock()
                raise EgressUnavailable(
                    f"proxy rotation acquisition failed: {type(exc).__name__}"
                ) from exc

    def _try_select_and_switch(
        self,
        *,
        cancel: Callable[[], bool] | None,
        deadline: float = 0.0,
    ) -> EgressLease:
        """Pick and verify a node. Caller holds the in-process and file locks."""
        if self._active is not None and not self._active.released:
            raise EgressUnavailable("proxy rotation lease is already active")

        info = self.controller.get_group(self.group)
        if info is None:
            raise EgressUnavailable(
                f"proxy rotation controller unavailable for group={self.group!r}"
            )
        all_names = [str(x) for x in (info.get("all") or []) if str(x).strip()]
        if not all_names:
            raise EgressUnavailable(f"proxy rotation group={self.group!r} has no nodes")
        nodes = self._filter_nodes(all_names)
        if not nodes:
            raise EgressUnavailable(
                f"proxy rotation group={self.group!r} has no eligible nodes"
            )
        self._nodes_cache = list(nodes)
        self._nodes_cache_at = time.time()

        initial_candidates = self._ordered_candidates(nodes, time.time())
        if not initial_candidates:
            raise EgressUnavailable("all eligible proxy egresses are cooling")

        attempts = 0
        tried: set[str] = set()
        last_failure = "max switch attempts exhausted"
        while attempts < self.max_switch_attempts:
            if cancel and cancel():
                raise EgressUnavailable("proxy rotation acquisition cancelled")
            if deadline and time.monotonic() >= deadline:
                raise EgressUnavailable("proxy rotation max wait exhausted")
            now = time.time()
            candidates = [n for n in self._ordered_candidates(nodes, now) if n not in tried]
            if not candidates:
                break

            node = candidates[0]
            tried.add(node)
            attempts += 1

            self.log(f"[proxy-rot] switch group={self.group} -> {node} (attempt {attempts})")
            if not self.controller.switch(self.group, node):
                last_failure = f"controller switch failed for node={node!r}"
                continue
            if not self._confirm_selection(node, cancel=cancel):
                last_failure = f"controller did not confirm node={node!r}"
                self.log(f"[proxy-rot] {last_failure}; try next")
                continue
            if self.switch_settle > 0:
                time.sleep(self.switch_settle)
            if cancel and cancel():
                raise EgressUnavailable("proxy rotation acquisition cancelled")
            if deadline and time.monotonic() >= deadline:
                raise EgressUnavailable("proxy rotation max wait exhausted")

            ip, country = self._probe_stable_egress(cancel=cancel)
            if not ip:
                last_failure = f"egress probe was unavailable or unstable after node={node!r}"
                self.log(f"[proxy-rot] probe unavailable/unstable after {node}; try next")
                continue

            self._node_last_ip[node] = ip
            if self.store.is_ip_cooling(ip, time.time()):
                last_failure = "all eligible proxy egresses are cooling"
                self.log(f"[proxy-rot] ip={ip} still cooling; skip node={node}")
                continue

            if self.require_us:
                if not country:
                    last_failure = f"country unknown for node={node!r}"
                    # Unknown metadata is fail-closed, but it is not evidence
                    # that the node is geographically invalid.  A transient
                    # probe/API omission must not exhaust the US node pool.
                    self.log(f"[proxy-rot] {last_failure}; try next node")
                    continue
                if country.upper() not in self.allowed_countries:
                    last_failure = f"country={country} is not allowed for node={node!r}"
                    self.log(
                        f"[proxy-rot] bad geo node={node} ip={ip} country={country}; cooldown node"
                    )
                    self.store.mark_bad_geo(node, self.cd_bad_geo)
                    continue

            lease = EgressLease(
                lease_id=uuid.uuid4().hex[:12],
                gateway=self.gateway,
                node_name=node,
                egress_ip=ip,
                country=country or "",
                acquired_at=time.time(),
                group=self.group,
                fixed=False,
            )
            self.log(
                f"[proxy-rot] acquire node={node} ip={ip} country={country or '?'} "
                f"lease={lease.lease_id}"
            )
            return lease

        if attempts >= self.max_switch_attempts:
            raise EgressUnavailable(f"max switch attempts exhausted: {last_failure}")
        raise EgressUnavailable(f"eligible proxy nodes exhausted: {last_failure}")

    def release(self, lease: EgressLease | None, outcome: str) -> None:
        if lease is None:
            return
        bookkeeping_error: Exception | None = None
        with self._condition:
            if lease.released:
                return
            lease.released = True
            normalized = (outcome or "").strip().lower()
            if normalized in {"generic_forbidden", "generic_403"}:
                normalized = "forbidden_unknown"
            cd = 0.0 if lease.fixed else self._cooldown_for_outcome(normalized)
            until = 0.0
            owns_active = self._active is lease
            try:
                if not lease.fixed and (lease.egress_ip or lease.node_name):
                    until = self.store.mark_outcome(
                        ip=lease.egress_ip,
                        node=lease.node_name,
                        outcome=normalized,
                        cooldown_sec=cd,
                    )
                if normalized == "egress_access_denied":
                    key = self._ip_hash(lease.egress_ip) or lease.node_name
                    if key and key not in self._egress_denied_keys:
                        self._egress_denied_keys.add(key)
                        self._consecutive_egress_denied = len(self._egress_denied_keys)
                else:
                    self._consecutive_egress_denied = 0
                    self._egress_denied_keys.clear()
                self._append_history("release", lease, outcome=normalized, cooldown_sec=cd)
                remain = max(0.0, until - time.time()) if until else cd
                self.log(
                    f"[proxy-rot] release lease={lease.lease_id} outcome={outcome} "
                    f"node={lease.node_name} ip={lease.egress_ip or '?'} "
                    f"cooldown={cd:.0f}s next_eligible_in={remain:.0f}s"
                )
            except Exception as exc:
                self.log(f"[proxy-rot] release bookkeeping failed: {exc}")
                bookkeeping_error = exc
            finally:
                if owns_active:
                    self._active = None
                if self.current_lease() is lease:
                    self.set_thread_lease(None)
                if owns_active:
                    self._release_process_lock()
                self._condition.notify_all()
        if bookkeeping_error is not None:
            raise EgressUnavailable(
                f"proxy rotation release bookkeeping failed: {type(bookkeeping_error).__name__}"
            ) from bookkeeping_error


def get_manager(config: dict[str, Any] | None = None, log: LogFn | None = None) -> EgressLeaseManager:
    """Process singleton; rebuild whenever any rotation behavior config changes."""
    global _manager, _manager_sig
    cfg = dict(config or {})
    behavior_config = {
        str(key): value
        for key, value in cfg.items()
        if str(key).startswith("proxy_rotation_") or key in {"proxy", "cpa_proxy"}
    }
    sig = (json.dumps(behavior_config, sort_keys=True, ensure_ascii=False, default=str),)
    with _manager_lock:
        if _manager is not None and _manager_sig == sig:
            if log is not None:
                _manager.log = log
            return _manager
        _manager = EgressLeaseManager(cfg, log=log)
        _manager_sig = sig
        return _manager


def map_registration_outcome(
    status: str,
    mint_result: dict[str, Any] | None = None,
) -> str:
    """Map CLI/GUI terminal status + mint result to cooldown outcome key."""
    s = (status or "").strip().lower()
    health = (mint_result or {}).get("health") if isinstance(mint_result, dict) else None
    classification = ""
    if isinstance(health, dict):
        classification = str(health.get("classification") or "").strip().lower()
    if classification == "healthy":
        return "healthy"
    if classification == "permission_denied":
        return "permission_denied"
    if classification == "egress_access_denied":
        return "egress_access_denied"
    if classification in {"forbidden_unknown", "generic_forbidden", "generic_403"}:
        return "forbidden_unknown"
    if classification == "endpoint_inconsistent":
        return "endpoint_inconsistent"
    if s in {"permission_denied", "rejected"}:
        return "permission_denied"
    if s in {"forbidden_unknown", "generic_forbidden", "generic_403"}:
        return "forbidden_unknown"
    if s == "endpoint_inconsistent":
        return "endpoint_inconsistent"
    if s in {"activation_failed"}:
        return "activation_failed"
    if s in {"cancelled", "cancel"}:
        return "cancelled"
    if s in {"failed", "reg_fail"}:
        return "reg_fail"
    if s in {"accepted", "healthy"}:
        if s == "healthy":
            return "healthy"
        if mint_result and mint_result.get("rejected"):
            return "permission_denied"
        return "soft_keep"
    if mint_result and mint_result.get("rejected"):
        return "permission_denied"
    return s or "failed"


# ── CLI smoke ─────────────────────────────────────────────────────────────────


def _load_local_config() -> dict[str, Any]:
    path = _ROOT / "config.json"
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {}
        # strip comment keys like the registrar does
        return {k: v for k, v in raw.items() if not str(k).startswith(("//", "#"))}
    except Exception:
        return {}


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Clash proxy rotation smoke tools")
    ap.add_argument("cmd", choices=["list", "switch", "probe", "version", "acquire-test"])
    ap.add_argument("--node", default="", help="node name for switch")
    ap.add_argument("--config", default="", help="path to config.json")
    args = ap.parse_args(argv)

    cfg = _load_local_config()
    if args.config:
        p = Path(args.config)
        cfg = {k: v for k, v in json.loads(p.read_text(encoding="utf-8")).items()
               if not str(k).startswith(("//", "#"))}

    mgr = get_manager(cfg)
    if args.cmd == "version":
        print(json.dumps(mgr.controller.version(), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "list":
        now, all_names = mgr.controller.list_group_nodes(mgr.group)
        us = mgr._filter_nodes(all_names)
        print(f"group={mgr.group} now={now}")
        print(f"all={len(all_names)} us_filtered={len(us)}")
        for n in us:
            print(f"  - {n}")
        return 0
    if args.cmd == "switch":
        node = args.node or (mgr._refresh_nodes() or [""])[0]
        if not node:
            print("no node")
            return 1
        ok = mgr.controller.switch(mgr.group, node)
        print(f"switch {node}: {ok}")
        if ok:
            time.sleep(mgr.switch_settle)
            ip, cc = probe_egress(mgr.gateway, urls=mgr.probe_urls, timeout=mgr.probe_timeout)
            print(f"egress ip={ip} country={cc}")
        return 0 if ok else 1
    if args.cmd == "probe":
        ip, cc = probe_egress(mgr.gateway, urls=mgr.probe_urls, timeout=mgr.probe_timeout)
        print(f"gateway={mgr.gateway} ip={ip} country={cc}")
        return 0 if ip else 1
    if args.cmd == "acquire-test":
        if not mgr.enabled:
            print("proxy_rotation_enabled is false; set true in config.json")
            return 1
        lease = mgr.acquire()
        print(json.dumps(lease.describe(), ensure_ascii=False, indent=2))
        mgr.release(lease, "soft_keep")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
