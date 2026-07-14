"""High-level: mint CPA xai-*.json for one free registered account."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable

from .browser_confirm import mint_with_browser
from .probe import probe_mini_response, probe_models
from .protocol_mint import ProtocolMintError, extract_sso_from_cookies, mint_with_sso_protocol
from .proxyutil import proxy_log_label, resolve_proxy, set_runtime_proxy
from .schema import DEFAULT_BASE_URL, build_cpa_xai_auth, jwt_payload
from .writer import write_cpa_xai_auth

LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    return None


def _safe_token_metadata(access_token: str) -> dict[str, Any]:
    try:
        claims = jwt_payload(access_token)
    except Exception:
        return {}
    subject = str(claims.get("sub") or claims.get("principal_id") or "")
    return {
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "scope": claims.get("scope") or claims.get("scp"),
        "client_id": claims.get("client_id") or claims.get("azp"),
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
        "sub_hash": hashlib.sha256(subject.encode()).hexdigest()[:16] if subject else "",
    }


def _wait_with_cancel(seconds: float, cancel: Callable[[], bool] | None) -> bool:
    deadline = time.monotonic() + max(0.0, float(seconds))
    while time.monotonic() < deadline:
        if cancel and cancel():
            return False
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    return not (cancel and cancel())


def _health_rejection_summary(health: dict[str, Any]) -> str:
    classification = str(health.get("classification") or "unknown")
    status = int(health.get("http_status") or 0)
    code = str(health.get("error_code") or "").strip()
    attempts = len(health.get("attempts") or [])
    parts = [classification]
    if status:
        parts.append(f"http={status}")
    if code:
        safe_code = "".join(ch for ch in code if ch.isalnum() or ch in "._-")[:80]
        if safe_code:
            parts.append(f"code={safe_code}")
    if attempts:
        parts.append(f"attempts={attempts}")
    return ":".join(parts)


def mint_and_export(
    *,
    email: str,
    password: str,
    auth_dir: str | Path,
    page: Any | None = None,
    proxy: str | None = None,
    headless: bool = False,
    base_url: str = DEFAULT_BASE_URL,
    probe: bool = True,
    probe_chat: bool = False,
    browser_timeout_sec: float = 240.0,
    force_standalone: bool = True,
    cookies: Any | None = None,
    sso: str | None = None,
    reuse_browser: bool = True,
    recycle_every: int = 15,
    prefer_protocol: bool = True,
    protocol_only: bool = False,
    protocol_poll_timeout_sec: float = 90.0,
    health_check: bool = False,
    health_probe_delays: list[float] | tuple[float, ...] = (0,),
    health_reject_inconclusive: bool = True,
    write_auth: bool = True,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Full pipeline: mint OIDC → optional health gate → optional write → legacy probe.

    Protocol path (curl_cffi + sso cookie) is tried first when prefer_protocol
    and an sso cookie is available. On failure, falls back to browser mint unless
    protocol_only=True.

    Returns dict with keys: ok, path, email, probe, error?, mint_method?
    """
    log = log or _noop
    email = (email or "").strip()
    if not email or not password:
        # Protocol can work with sso alone; password only required for browser fallback
        if not email:
            return {"ok": False, "email": email, "error": "missing email"}
        if not (sso or extract_sso_from_cookies(cookies)):
            return {"ok": False, "email": email, "error": "missing email/password"}

    # Config/explicit proxy wins over shell https_proxy (common 7890 trap).
    # Thread-local pin — safe under concurrent mint workers.
    resolved = resolve_proxy(proxy)
    set_runtime_proxy(resolved or None)
    log(f"mint start: {email} proxy={proxy_log_label(resolved) or '(none)'}")

    sso_val = (sso or "").strip() or extract_sso_from_cookies(cookies)
    tokens: dict[str, Any] | None = None
    protocol_err: str | None = None

    if prefer_protocol and sso_val:
        log("mint try protocol (SSO HTTP device flow)")
        try:
            tokens = mint_with_sso_protocol(
                sso_cookie=sso_val,
                email=email,
                proxy=resolved or None,
                poll_timeout_sec=protocol_poll_timeout_sec,
                log=log,
                cancel=cancel,
            )
            log("mint protocol SUCCESS")
        except ProtocolMintError as e:
            protocol_err = str(e)
            log(f"mint protocol failed: {e}")
            if cancel and cancel():
                return {"ok": False, "email": email, "error": "cancelled"}
            if protocol_only:
                return {
                    "ok": False,
                    "email": email,
                    "error": f"protocol_only: {e}",
                    "mint_method": "protocol",
                }
            log("mint fallback → browser")
        except Exception as e:  # noqa: BLE001
            protocol_err = str(e)
            log(f"mint protocol exception: {e}")
            if protocol_only:
                return {
                    "ok": False,
                    "email": email,
                    "error": f"protocol_only: {e}",
                    "mint_method": "protocol",
                }
            log("mint fallback → browser")
    elif prefer_protocol and not sso_val:
        log("mint protocol skipped (no sso cookie) → browser")
        if protocol_only:
            return {
                "ok": False,
                "email": email,
                "error": "protocol_only but no sso cookie",
                "mint_method": "protocol",
            }
    elif not prefer_protocol:
        log("mint protocol disabled → browser")

    if tokens is None:
        if cancel and cancel():
            return {"ok": False, "email": email, "error": "cancelled"}
        if not password:
            return {
                "ok": False,
                "email": email,
                "error": protocol_err or "protocol failed and no password for browser fallback",
                "protocol_error": protocol_err,
            }
        try:
            tokens = mint_with_browser(
                email=email,
                password=password,
                page=None if force_standalone else page,
                proxy=resolved or None,
                headless=headless,
                browser_timeout_sec=browser_timeout_sec,
                force_standalone=force_standalone,
                cookies=cookies,
                reuse_browser=reuse_browser,
                recycle_every=recycle_every,
                poll_log=log,
                cancel=cancel,
            )
            tokens["mint_method"] = "browser"
            if protocol_err:
                tokens["protocol_error"] = protocol_err
        except Exception as e:  # noqa: BLE001
            log(f"mint failed: {e}")
            err = str(e)
            if protocol_err:
                err = f"{err} (protocol: {protocol_err})"
            return {
                "ok": False,
                "email": email,
                "error": err,
                "protocol_error": protocol_err,
            }

    result: dict[str, Any] = {
        "ok": True,
        "email": email,
        "user_code": tokens.get("user_code"),
        "base_url": base_url,
        "proxy": proxy_log_label(resolved),
        "mint_method": tokens.get("mint_method") or "browser",
        "token_metadata": _safe_token_metadata(str(tokens.get("access_token") or "")),
    }
    if protocol_err and result["mint_method"] != "protocol":
        result["protocol_error"] = protocol_err

    if cancel and cancel():
        return {**result, "ok": False, "error": "cancelled"}

    if health_check:
        from .inspection import aggregate_health_attempts, inspect_access_token

        delays = sorted({max(0.0, float(value)) for value in (health_probe_delays or (0,))})
        if not delays:
            delays = [0.0]
        health_started = time.monotonic()
        attempts: list[dict[str, Any]] = []
        for attempt_index, offset in enumerate(delays, 1):
            remaining = offset - (time.monotonic() - health_started)
            if remaining > 0 and not _wait_with_cancel(remaining, cancel):
                return {**result, "ok": False, "error": "cancelled"}
            try:
                attempt = inspect_access_token(
                    tokens["access_token"],
                    base_url=base_url,
                    proxy=resolved or None,
                )
            except Exception as exc:  # noqa: BLE001
                attempt = {
                    "classification": "probe_error",
                    "confidence": "inconclusive",
                    "http_status": 0,
                    "error_message": str(exc),
                }
            attempt["attempt"] = attempt_index
            attempt["offset_sec"] = offset
            attempts.append(attempt)
            log(
                "health attempt=%s/%s classification=%s confidence=%s "
                "status=%s code=%s fallback=%s error=%s"
                % (
                    attempt_index,
                    len(delays),
                    attempt.get("classification"),
                    attempt.get("confidence"),
                    attempt.get("http_status"),
                    attempt.get("error_code"),
                    attempt.get("fallback_status"),
                    str(attempt.get("error_message") or "")[:200],
                )
            )
            if attempt.get("classification") == "healthy":
                break

        health = aggregate_health_attempts(
            attempts,
            reject_inconclusive=health_reject_inconclusive,
        )
        result["health"] = health
        log(
            "health: classification=%s status=%s model=%s error=%s"
            % (
                health.get("classification"),
                health.get("http_status"),
                health.get("model"),
                str(health.get("error_message") or "")[:200],
            )
        )
        if health.get("reject_candidate"):
            result["ok"] = False
            result["rejected"] = True
            result["error"] = health.get("reason") or "health gate rejected candidate"
            result["rejection_summary"] = _health_rejection_summary(health)
            return result

    if cancel and cancel():
        return {**result, "ok": False, "error": "cancelled"}

    payload = build_cpa_xai_auth(
        email=email,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        id_token=tokens.get("id_token"),
        expires_in=tokens.get("expires_in"),
        base_url=base_url,
    )
    if write_auth:
        path = write_cpa_xai_auth(auth_dir, payload)
        result["path"] = str(path)
        log(f"wrote {path}")
        if cancel and cancel():
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
            result.pop("path", None)
            result["ok"] = False
            result["error"] = "cancelled"
            return result
    else:
        result["export_skipped"] = True
        log("health-only mint complete; CPA file export disabled")

    if probe and write_auth:
        pr = probe_models(tokens["access_token"], base_url=base_url, proxy=resolved or None)
        result["probe_models"] = pr
        log(
            f"probe models: ok={pr.get('ok')} status={pr.get('status')} "
            f"has_grok_45={pr.get('has_grok_45')} ids={pr.get('model_ids')} "
            f"error={str(pr.get('error') or '')[:200]}"
        )
        if not pr.get("has_grok_45"):
            result["ok"] = False
            result["error"] = "token ok but grok-4.5 not listed"
        if probe_chat and pr.get("has_grok_45"):
            ch = probe_mini_response(
                tokens["access_token"], base_url=base_url, proxy=resolved or None
            )
            result["probe_chat"] = ch
            log(f"probe chat: ok={ch.get('ok')} model={ch.get('model')} text={ch.get('text')!r}")
            if not ch.get("ok"):
                result["ok"] = False
                result["error"] = f"chat probe failed: {ch.get('error') or ch.get('status')}"
    return result
