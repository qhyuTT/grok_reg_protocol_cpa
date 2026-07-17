"""Register-machine hook: mint CPA xai auth after successful registration.

OIDC package lives at ./cpa_xai (bundled with this project).
Optional override: config `api_reverse_tools` / env `API_REVERSE_TOOLS`
points at a directory that *contains* the `cpa_xai` package.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

_REG_DIR = Path(__file__).resolve().parent
_DEFAULT_OUT = _REG_DIR / "cpa_auths"
_DEFAULT_CPA = Path("")  # empty = do not assume a machine-local CPA path
_health_audit_lock = threading.Lock()


def _parse_health_delays(value: Any) -> list[float]:
    if isinstance(value, str):
        values = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        values = [10, 20, 45]
    parsed = []
    for item in values:
        try:
            parsed.append(max(0.0, float(item)))
        except (TypeError, ValueError):
            continue
    return sorted(set(parsed)) or [10.0, 20.0, 45.0]


def _redact_audit_text(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    # Redact before truncation. Otherwise a long JWT can be cut mid-signature
    # and no longer match the three-segment pattern, leaking its prefix.
    text = re.sub(
        r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        "<redacted:jwt>",
        text,
    )
    text = re.sub(
        r'''(?ix)
        (\b(?:access_token|refresh_token|id_token|authorization|sso(?:-rw)?|token)\b
        ["']?\s*[:=]\s*["']?(?:bearer\s+)?)
        [^\s,"';&}]+
        ''',
        r"\1<redacted>",
        text,
    )
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted:email>", text)
    return text[:limit]


def _health_attempt_for_audit(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "attempt": item.get("attempt"),
        "offset_sec": item.get("offset_sec"),
        "token_age_sec": item.get("token_age_sec"),
        "classification": item.get("classification"),
        "confidence": item.get("confidence"),
        "model": item.get("model"),
        "models_status": item.get("models_status"),
        "responses_status": item.get("http_status"),
        "responses_code": item.get("error_code"),
        "responses_message": _redact_audit_text(item.get("error_message")),
        "responses_content_type": item.get("responses_content_type"),
        "responses_duration_ms": item.get("responses_duration_ms"),
        "responses_raw_snippet": _redact_audit_text(item.get("responses_raw_snippet")),
        "fallback_status": item.get("fallback_status"),
        "fallback_code": item.get("fallback_error_code"),
        "fallback_message": _redact_audit_text(item.get("fallback_error_message")),
        "fallback_content_type": item.get("fallback_content_type"),
        "fallback_duration_ms": item.get("fallback_duration_ms"),
        "fallback_raw_snippet": _redact_audit_text(item.get("fallback_raw_snippet")),
        "headers_profile": item.get("headers_profile") or {},
    }


def _write_health_audit(
    *,
    result: dict[str, Any],
    email: str,
    cfg: dict[str, Any],
    log: Callable[[str], None],
) -> None:
    health = result.get("health")
    if not isinstance(health, dict):
        return
    raw_path = str(
        cfg.get("registration_health_audit_file")
        or "cpa_auths/registration_health_audit.jsonl"
    ).strip()
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = (_REG_DIR / path).resolve()
    egress: dict[str, Any] = {}
    raw_egress = cfg.get("_egress")
    if isinstance(raw_egress, dict):
        egress = raw_egress
    else:
        try:
            import proxy_rotation as _proxy_rot

            meta = _proxy_rot.get_manager(cfg).current_lease_metadata()
            if isinstance(meta, dict):
                egress = meta
        except Exception:
            egress = {}
    record = {
        "timestamp": int(time.time()),
        "email": email,
        "mint_method": result.get("mint_method"),
        "proxy": result.get("proxy"),
        "egress_ip": str(egress.get("egress_ip") or ""),
        "egress_country": str(egress.get("country") or ""),
        "clash_node": str(egress.get("node_name") or ""),
        "proxy_lease_id": str(egress.get("lease_id") or ""),
        "token_metadata": result.get("token_metadata") or {},
        "classification": health.get("classification"),
        "confidence": health.get("confidence"),
        "reject_candidate": bool(health.get("reject_candidate")),
        "reject_reason": health.get("reject_reason"),
        "reason": _redact_audit_text(health.get("reason")),
        "attempts": [
            _health_attempt_for_audit(dict(item))
            for item in (health.get("attempts") or [])
            if isinstance(item, dict)
        ],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _health_audit_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            os.chmod(path, 0o600)
        log(f"[health] 审计记录已写入: {path}")
    except Exception as exc:  # noqa: BLE001
        log(f"[health] 审计记录写入失败: {exc}")


def _ensure_cpa_xai_on_path(tools_dir: str | Path | None = None) -> Path:
    """Put the parent of `cpa_xai` on sys.path. Default: this project root."""
    if tools_dir:
        tools = Path(tools_dir).expanduser().resolve()
    else:
        env = (os.environ.get("API_REVERSE_TOOLS") or "").strip()
        tools = Path(env).expanduser().resolve() if env else _REG_DIR
    # If user pointed at .../cpa_xai itself, use its parent
    if tools.name == "cpa_xai" and (tools / "__init__.py").is_file():
        tools = tools.parent
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    return tools


def export_cookies_from_page(page: Any) -> list[dict]:
    """Best-effort export of cookies from a DrissionPage tab/browser."""
    if page is None:
        return []
    cookies = None
    for getter in (
        lambda: page.cookies(all_domains=True, all_info=True),
        lambda: page.cookies(all_domains=True),
        lambda: page.cookies(),
    ):
        try:
            cookies = getter()
            if cookies:
                break
        except TypeError:
            continue
        except Exception:
            continue
    if not cookies:
        try:
            browser = getattr(page, "browser", None)
            if browser is not None:
                cookies = browser.cookies()
        except Exception:
            cookies = None
    if isinstance(cookies, list):
        return [c for c in cookies if isinstance(c, dict)]
    return []


def export_cpa_xai_for_account(
    email: str,
    password: str,
    *,
    page: Any | None = None,
    cookies: Any | None = None,
    sso: str | None = None,
    config: dict | None = None,
    log_callback: Callable[[str], None] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict:
    """Mint OIDC + write xai-<email>.json under register cpa_auths (and optional CPA auth-dir)."""
    cfg = config or {}
    log = log_callback or (lambda m: print(m, flush=True))

    export_enabled = bool(cfg.get("cpa_export_enabled", True))
    health_enabled = bool(cfg.get("registration_health_check_enabled", False))
    if not export_enabled and not health_enabled:
        log("[cpa] export disabled")
        return {"ok": False, "skipped": True, "reason": "disabled"}

    tools_dir = cfg.get("api_reverse_tools") or cfg.get("cpa_xai_parent") or None
    _ensure_cpa_xai_on_path(tools_dir)

    try:
        from cpa_xai import mint_and_export  # type: ignore
    except Exception as e:  # noqa: BLE001
        log(f"[cpa] import cpa_xai failed: {e}")
        return {"ok": False, "error": f"import: {e}"}

    out_dir = Path(cfg.get("cpa_auth_dir") or _DEFAULT_OUT).expanduser()
    if not out_dir.is_absolute():
        out_dir = (_REG_DIR / out_dir).resolve()

    hotload_raw = (cfg.get("cpa_hotload_dir") or "").strip()
    cpa_dir = Path(hotload_raw).expanduser() if hotload_raw else None
    if cpa_dir and not cpa_dir.is_absolute():
        cpa_dir = (_REG_DIR / cpa_dir).resolve()

    # Priority: cpa_proxy > proxy > env. Config must beat shell https_proxy.
    proxy = (cfg.get("cpa_proxy") or cfg.get("proxy") or "").strip()
    if not proxy:
        proxy = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or ""
        ).strip()
    # Default headed: headless is frequently Cloudflare-blocked on accounts.x.ai
    headless = bool(cfg.get("cpa_headless", False))
    probe = bool(cfg.get("cpa_probe_after_write", True))
    probe_chat = bool(cfg.get("cpa_probe_chat", False))
    timeout = float(cfg.get("cpa_mint_timeout_sec", 240))
    base_url = cfg.get("cpa_base_url") or "https://cli-chat-proxy.grok.com/v1"
    force_standalone = bool(cfg.get("cpa_force_standalone", True))
    cookie_inject = bool(cfg.get("cpa_mint_cookie_inject", True))
    reuse_browser = bool(cfg.get("cpa_mint_browser_reuse", True))
    recycle_every = int(cfg.get("cpa_mint_browser_recycle_every", 15) or 0)
    # Auth-code PKCE (referrer=grok-build) first; then device protocol; browser last.
    prefer_auth_code = bool(cfg.get("cpa_prefer_auth_code", True))
    prefer_protocol = bool(cfg.get("cpa_prefer_protocol", True))
    protocol_only = bool(cfg.get("cpa_protocol_only", False))
    protocol_poll_timeout = float(cfg.get("cpa_protocol_poll_timeout_sec", 90) or 90)
    auth_code_timeout = float(cfg.get("cpa_auth_code_timeout_sec", 90) or 90)
    auth_code_require_referrer = bool(cfg.get("cpa_auth_code_require_referrer", True))
    if "cpa_required_referrer" in cfg:
        raw_required_referrer = cfg.get("cpa_required_referrer")
        required_referrer = (
            "" if raw_required_referrer is None else str(raw_required_referrer).strip()
        )
    else:
        # Backward compatibility: the old auth-code-only switch now controls
        # the pipeline-wide policy when the new key is absent.
        required_referrer = "grok-build" if auth_code_require_referrer else ""
    health_probe_delays = _parse_health_delays(
        cfg.get("registration_health_probe_delays_sec", [10, 20, 45])
    )
    health_reject_inconclusive = bool(
        cfg.get("registration_health_reject_inconclusive", True)
    )

    # cookies: explicit arg > page export > none
    use_cookies = cookies
    if use_cookies is None and cookie_inject and page is not None:
        use_cookies = export_cookies_from_page(page)
    if not cookie_inject:
        use_cookies = None
    else:
        # Always attach SSO cookie clones — register cookies alone often miss accounts.x.ai host
        sso_val = (sso or "").strip()
        if not sso_val and isinstance(use_cookies, list):
            for c in use_cookies:
                if isinstance(c, dict) and c.get("name") in ("sso", "sso-rw") and c.get("value"):
                    sso_val = str(c.get("value"))
                    break
        if sso_val:
            base = list(use_cookies) if isinstance(use_cookies, list) else []
            for name in ("sso", "sso-rw"):
                for dom in (".x.ai", "accounts.x.ai", ".accounts.x.ai", "auth.x.ai", "grok.com", ".grok.com"):
                    base.append({
                        "name": name,
                        "value": sso_val,
                        "domain": dom,
                        "path": "/",
                        "secure": True,
                        "httpOnly": True,
                    })
            use_cookies = base

    sso_val = (sso or "").strip()
    if not sso_val and isinstance(use_cookies, list):
        for c in use_cookies:
            if isinstance(c, dict) and c.get("name") in ("sso", "sso-rw") and c.get("value"):
                sso_val = str(c.get("value"))
                break

    out_dir.mkdir(parents=True, exist_ok=True)
    log(
        f"[cpa] mint OIDC for {email} -> {out_dir} proxy={proxy or '(none)'} "
        f"cookies={len(use_cookies) if isinstance(use_cookies, list) else (1 if use_cookies else 0)} "
        f"reuse={reuse_browser} auth_code={prefer_auth_code} protocol={prefer_protocol}"
        f"{' only' if protocol_only else ''} sso={'yes' if sso_val else 'no'}"
    )

    def _log(msg: str) -> None:
        log(f"[cpa] {msg}")

    result = mint_and_export(
        email=email,
        password=password,
        auth_dir=out_dir,
        page=None if force_standalone else page,
        proxy=proxy or None,
        headless=headless,
        base_url=base_url,
        probe=probe,
        probe_chat=probe_chat,
        browser_timeout_sec=timeout,
        force_standalone=force_standalone,
        cookies=use_cookies,
        sso=sso_val or None,
        reuse_browser=reuse_browser,
        recycle_every=recycle_every,
        prefer_auth_code=prefer_auth_code,
        prefer_protocol=prefer_protocol,
        protocol_only=protocol_only,
        protocol_poll_timeout_sec=protocol_poll_timeout,
        auth_code_timeout_sec=auth_code_timeout,
        auth_code_require_referrer=auth_code_require_referrer,
        required_referrer=required_referrer,
        health_check=health_enabled,
        health_probe_delays=health_probe_delays,
        health_reject_inconclusive=health_reject_inconclusive,
        write_auth=export_enabled,
        log=_log,
        cancel=cancel,
    )
    if result.get("mint_method"):
        log(f"[cpa] mint_method={result.get('mint_method')}")
    _write_health_audit(result=result, email=email, cfg=cfg, log=log)

    if cancel and cancel():
        for key in ("cpa_path", "path"):
            raw_path = result.get(key)
            if raw_path:
                try:
                    Path(raw_path).unlink(missing_ok=True)
                except OSError:
                    pass
                result.pop(key, None)
        result["ok"] = False
        result["error"] = "cancelled"
        return result

    # By default, a failed post-write probe is only a warning: the CPA auth file
    # has already been minted and written. Set cpa_probe_required=true to make
    # missing /models grok-4.5 fail the export.
    if (
        not result.get("ok")
        and result.get("path")
        and str(result.get("error") or "").startswith("token ok but grok-4.5 not listed")
        and not cfg.get("cpa_probe_required", False)
    ):
        result["ok"] = True
        result["probe_warning"] = result.pop("error", "probe failed")
        log(f"[cpa] probe warning ignored (file already written): {result.get('probe_warning')}")

    if result.get("ok") and result.get("path") and cfg.get("cpa_copy_to_hotload", False) and cpa_dir:
        try:
            cpa_dir.mkdir(parents=True, exist_ok=True)
            src = Path(result["path"])
            dst = cpa_dir / src.name
            shutil.copy2(src, dst)
            os.chmod(dst, 0o600)
            result["cpa_path"] = str(dst)
            log(f"[cpa] hotload copy -> {dst}")
        except Exception as e:  # noqa: BLE001
            log(f"[cpa] hotload copy failed: {e}")
            result["cpa_copy_error"] = str(e)

    # failure log under register dir
    if not result.get("ok") and not result.get("rejected"):
        fail_path = out_dir / "cpa_auth_failed.txt"
        with open(fail_path, "a", encoding="utf-8") as f:
            f.write(f"{email}----{result.get('error') or 'unknown'}----{int(time.time())}\n")
        if cfg.get("cpa_mint_required", False):
            raise RuntimeError(f"CPA mint required but failed: {result.get('error')}")

    return result
