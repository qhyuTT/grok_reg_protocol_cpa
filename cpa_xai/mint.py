"""High-level: mint CPA xai-*.json for one free registered account."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable

from .auth_code_mint import AuthCodeMintError, GROK_REFERRER, mint_with_sso_auth_code
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
        "referrer": claims.get("referrer"),
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


def _resolve_required_referrer(
    required_referrer: str | None,
    auth_code_require_referrer: bool,
) -> str:
    """Resolve the pipeline-wide referrer policy with legacy compatibility."""

    if required_referrer is None:
        return GROK_REFERRER if auth_code_require_referrer else ""
    return str(required_referrer).strip()


def _token_referrer(tokens: dict[str, Any]) -> str:
    raw = str(tokens.get("referrer") or "").strip()
    if raw:
        return raw
    try:
        claims = jwt_payload(str(tokens.get("access_token") or ""))
    except Exception:
        return ""
    return str(claims.get("referrer") or "").strip()


def _referrer_policy_error(
    tokens: dict[str, Any],
    *,
    method: str,
    required_referrer: str,
) -> str | None:
    actual = _token_referrer(tokens)
    tokens["referrer"] = actual
    if required_referrer and actual != required_referrer:
        return (
            f"{method} token referrer={actual!r}; "
            f"expected {required_referrer!r}"
        )
    return None


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
    prefer_auth_code: bool = True,
    prefer_protocol: bool = True,
    protocol_only: bool = False,
    protocol_poll_timeout_sec: float = 90.0,
    auth_code_timeout_sec: float = 90.0,
    auth_code_require_referrer: bool = True,
    required_referrer: str | None = None,
    health_check: bool = False,
    health_probe_delays: list[float] | tuple[float, ...] = (10, 20, 45),
    health_reject_inconclusive: bool = True,
    write_auth: bool = True,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Full pipeline: mint OIDC → optional health gate → optional write → legacy probe.

    Mint order when SSO is available:
      1) Authorization Code + PKCE (``referrer=grok-build``) if prefer_auth_code
      2) Device-code protocol HTTP if prefer_protocol
      3) Browser device consent (unless protocol_only)

    Returns dict with keys: ok, path, email, probe, error?, mint_method?
    """
    log = log or _noop
    pipeline_referrer = _resolve_required_referrer(
        required_referrer, auth_code_require_referrer
    )
    email = (email or "").strip()
    if not email or not password:
        # Auth-code/protocol can work with sso alone; password only for browser fallback
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
    auth_code_err: str | None = None

    if prefer_auth_code and sso_val:
        log("mint try auth-code (SSO PKCE referrer=grok-build)")
        try:
            tokens = mint_with_sso_auth_code(
                sso_cookie=sso_val,
                email=email,
                proxy=resolved or None,
                total_timeout_sec=auth_code_timeout_sec,
                require_referrer=False,
                required_referrer="",
                log=log,
                cancel=cancel,
            )
            policy_error = _referrer_policy_error(
                tokens,
                method="auth-code",
                required_referrer=pipeline_referrer,
            )
            if policy_error:
                raise AuthCodeMintError(policy_error)
            log("mint auth-code SUCCESS")
        except AuthCodeMintError as e:
            auth_code_err = str(e)
            tokens = None
            log(f"mint auth-code failed: {e}")
            if cancel and cancel():
                return {"ok": False, "email": email, "error": "cancelled"}
        except Exception as e:  # noqa: BLE001
            auth_code_err = str(e)
            tokens = None
            log(f"mint auth-code exception: {e}")
            if cancel and cancel():
                return {"ok": False, "email": email, "error": "cancelled"}
    elif prefer_auth_code and not sso_val:
        log("mint auth-code skipped (no sso cookie)")

    if tokens is None and prefer_protocol and sso_val:
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
            policy_error = _referrer_policy_error(
                tokens,
                method="protocol",
                required_referrer=pipeline_referrer,
            )
            if policy_error:
                raise ProtocolMintError(policy_error)
            log("mint protocol SUCCESS")
        except ProtocolMintError as e:
            protocol_err = str(e)
            tokens = None
            log(f"mint protocol failed: {e}")
            if cancel and cancel():
                return {"ok": False, "email": email, "error": "cancelled"}
            if protocol_only:
                return {
                    "ok": False,
                    "email": email,
                    "error": f"protocol_only: {e}",
                    "mint_method": "protocol",
                    "auth_code_error": auth_code_err,
                }
            log("mint fallback → browser")
        except Exception as e:  # noqa: BLE001
            protocol_err = str(e)
            tokens = None
            log(f"mint protocol exception: {e}")
            if protocol_only:
                return {
                    "ok": False,
                    "email": email,
                    "error": f"protocol_only: {e}",
                    "mint_method": "protocol",
                    "auth_code_error": auth_code_err,
                }
            log("mint fallback → browser")
    elif tokens is None and prefer_protocol and not sso_val:
        log("mint protocol skipped (no sso cookie) → browser")
        if protocol_only:
            return {
                "ok": False,
                "email": email,
                "error": "protocol_only but no sso cookie",
                "mint_method": "protocol",
                "auth_code_error": auth_code_err,
            }
    elif tokens is None and not prefer_protocol:
        log("mint protocol disabled → browser")

    if tokens is None:
        if cancel and cancel():
            return {"ok": False, "email": email, "error": "cancelled"}
        if protocol_only:
            return {
                "ok": False,
                "email": email,
                "error": protocol_err
                or auth_code_err
                or "protocol_only and no tokens",
                "protocol_error": protocol_err,
                "auth_code_error": auth_code_err,
            }
        if not password:
            return {
                "ok": False,
                "email": email,
                "error": protocol_err
                or auth_code_err
                or "mint failed and no password for browser fallback",
                "protocol_error": protocol_err,
                "auth_code_error": auth_code_err,
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
            policy_error = _referrer_policy_error(
                tokens,
                method="browser",
                required_referrer=pipeline_referrer,
            )
            if policy_error:
                raise AuthCodeMintError(policy_error)
            if protocol_err:
                tokens["protocol_error"] = protocol_err
            if auth_code_err:
                tokens["auth_code_error"] = auth_code_err
        except Exception as e:  # noqa: BLE001
            log(f"mint failed: {e}")
            err = str(e)
            if protocol_err:
                err = f"{err} (protocol: {protocol_err})"
            if auth_code_err:
                err = f"{err} (auth_code: {auth_code_err})"
            return {
                "ok": False,
                "email": email,
                "error": err,
                "protocol_error": protocol_err,
                "auth_code_error": auth_code_err,
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
    if auth_code_err and result["mint_method"] != "auth_code":
        result["auth_code_error"] = auth_code_err
    if protocol_err and result["mint_method"] not in {"protocol", "auth_code"}:
        result["protocol_error"] = protocol_err

    if cancel and cancel():
        return {**result, "ok": False, "error": "cancelled"}

    if health_check:
        from .inspection import aggregate_health_attempts, inspect_access_token

        delays = sorted(
            {
                max(0.0, float(value))
                for value in (health_probe_delays or (10, 20, 45))
            }
        )
        if not delays:
            delays = [10.0, 20.0, 45.0]
        health_started = time.monotonic()
        attempts: list[dict[str, Any]] = []
        token_iat = result["token_metadata"].get("iat")
        for attempt_index, offset in enumerate(delays, 1):
            remaining = offset - (time.monotonic() - health_started)
            if remaining > 0 and not _wait_with_cancel(remaining, cancel):
                return {**result, "ok": False, "error": "cancelled"}
            token_age_sec = None
            if isinstance(token_iat, (int, float)):
                token_age_sec = round(max(0.0, time.time() - float(token_iat)), 3)
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
            if token_age_sec is not None:
                attempt["token_age_sec"] = token_age_sec
            attempts.append(attempt)
            log(
                "health attempt=%s/%s offset=%ss token_age=%s classification=%s confidence=%s "
                "status=%s code=%s fallback=%s error=%s"
                % (
                    attempt_index,
                    len(delays),
                    offset,
                    f"{token_age_sec:.3f}s" if token_age_sec is not None else "?",
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
