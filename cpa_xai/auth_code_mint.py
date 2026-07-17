"""SSO cookie → OIDC tokens via Authorization Code + PKCE.

Device-code grants omit the JWT ``referrer`` claim; cli-chat-proxy then
returns ``permission-denied`` on chat. This path injects
``referrer=grok-build`` on authorize and consent, plus ``plan=generic`` on
authorize, so the access_token carries the claim (aligned with
grok-build-auth / grokRegister-cpa).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.parse
from typing import Any, Callable

from curl_cffi import requests as cf_requests

from .proxyutil import resolve_proxy
from .schema import CLIENT_ID, DEFAULT_REDIRECT_URI, ISSUER

LogFn = Callable[[str], None]

OIDC_ISSUER = ISSUER
SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)
GROK_REFERRER = "grok-build"
GROK_PLAN = "generic"
GROK_VERSION = "0.2.93"
GROK_TOKEN_UA = f"grok-pager/{GROK_VERSION} grok-shell/{GROK_VERSION} (linux; x86_64)"
# Next.js Server Action id for consent allow (fallback; JS scan on miss).
NEXT_ACTION_ID = "401b73e22a5e68737d0037e1aa449fef82cd1b35fb"

_working_next_action_id = NEXT_ACTION_ID
_NEXT_ACTION_RE = re.compile(
    r'(?:\$ACTION_ID_|next-action["\']?\s*[:=]\s*["\']|["\'])([0-9a-f]{40,44})["\']',
    re.I,
)
_CREATE_SERVER_REF_RE = re.compile(
    r'createServerReference\)?\(["\']([0-9a-f]{40,44})["\']',
    re.I,
)
_CALL_SERVER_RE = re.compile(
    r'["\']([0-9a-f]{40,44})["\']\s*,\s*(?:callServer|findSourceMapURL)',
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)(code|state|token|sso|access_token|refresh_token|id_token)=([^&\s]+)"
)
_SENSITIVE_VALUE_RE = re.compile(
    r'''(?ix)
    (\b(?:access_token|refresh_token|id_token|authorization|sso(?:-rw)?|token)\b
    ["']?\s*[:=]\s*["']?(?:bearer\s+)?)
    [^\s,"';&}]+
    '''
)
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

EXPECTED_REFERRERS = frozenset({GROK_REFERRER})
MAX_REDIRECT_HOPS = 8


class AuthCodeMintError(RuntimeError):
    """Authorization-code mint failed."""


def _noop(_: str) -> None:
    return None


def _redact_error(value: Any) -> str:
    text = _JWT_RE.sub("<redacted:jwt>", str(value or ""))
    text = _SENSITIVE_QUERY_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    return _SENSITIVE_VALUE_RE.sub(r"\1<redacted>", text)


def _check_active(
    cancel: Callable[[], bool] | None,
    deadline: float,
) -> None:
    if cancel and cancel():
        raise AuthCodeMintError("cancelled")
    if time.monotonic() >= deadline:
        raise AuthCodeMintError("auth-code total timeout")


def _request_timeout(timeout: float, deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AuthCodeMintError("auth-code total timeout")
    return max(0.01, min(float(timeout), remaining))


def _is_loopback_url(url: str) -> bool:
    try:
        host = str(urllib.parse.urlparse(str(url or "")).hostname or "").strip().lower()
    except Exception:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _redirect_endpoint(url: str) -> tuple[str, str, int | None, str]:
    parsed = urllib.parse.urlparse(str(url or ""))
    try:
        port = parsed.port
    except ValueError as exc:
        raise AuthCodeMintError("oauth callback redirect URI mismatch") from exc
    return (
        parsed.scheme.lower(),
        str(parsed.hostname or "").lower(),
        port,
        parsed.path or "/",
    )


def _is_expected_callback(
    url: str,
    expected_redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> bool:
    return _redirect_endpoint(url) == _redirect_endpoint(expected_redirect_uri)


def _oauth_query(url: str) -> dict[str, list[str]]:
    parsed = urllib.parse.urlparse(str(url or ""))
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        query.setdefault(key, values)
    return query


def _callback_code(
    url: str,
    expected_state: str,
    expected_redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str | None:
    query = _oauth_query(url)
    code = str((query.get("code") or [""])[0]).strip()
    error = str((query.get("error") or [""])[0]).strip()
    has_oauth_response = bool(code or error)
    if not has_oauth_response:
        return None
    if not _is_expected_callback(url, expected_redirect_uri):
        raise AuthCodeMintError("oauth callback redirect URI mismatch")
    returned_state = str((query.get("state") or [""])[0]).strip()
    if not returned_state or returned_state != expected_state:
        raise AuthCodeMintError("oauth callback state mismatch")
    if error:
        description = str((query.get("error_description") or [""])[0]).strip()
        detail = f": {_redact_error(description)[:160]}" if description else ""
        raise AuthCodeMintError(f"oauth callback error={_redact_error(error)}{detail}")
    return code


def _response_header(response: Any, name: str) -> str:
    headers = getattr(response, "headers", {}) or {}
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    return str(value or "").strip()


def _normalise_redirect_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for _ in range(2):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return (
        text.replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\/", "/")
        .strip(" \t\r\n\"'")
    )


def _redirect_candidates(response: Any, body: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        candidate = _normalise_redirect_value(value)
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        candidates.append(candidate)

    for name in ("Location", "X-Action-Redirect", "X-Nextjs-Redirect"):
        raw = _response_header(response, name)
        if not raw:
            continue
        _add(raw)
        for match in re.findall(r"https?://[^\s\"'<>]+", _normalise_redirect_value(raw)):
            _add(match)

    normalised_body = _normalise_redirect_value(body)
    for match in re.findall(r"https?://[^\s\"'<>]+", normalised_body):
        _add(match)
    return candidates


def _origin_for_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise AuthCodeMintError("consent URL has no valid origin")
    return f"{parsed.scheme.lower()}://{parsed.netloc}"


def _is_trusted_oauth_redirect(url: str) -> bool:
    parsed = urllib.parse.urlparse(str(url or ""))
    return (
        parsed.scheme.lower() == "https"
        and str(parsed.hostname or "").lower()
        in {"accounts.x.ai", "auth.x.ai"}
    )


def decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return {}
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def access_token_referrer(access_token: str) -> str:
    return str(decode_jwt_payload(access_token).get("referrer") or "").strip()


def _gen_pkce() -> tuple[str, str, str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    return verifier, challenge, state, nonce


def _parse_consent_code(body: str) -> str | None:
    for line in (body or "").split("\n"):
        start = line.find("{")
        if start < 0:
            continue
        try:
            data = json.loads(line[start:])
        except Exception:
            continue
        if isinstance(data, dict) and data.get("code"):
            if data.get("success") is False:
                return None
            return str(data.get("code") or "") or None
    return None


def _callback_target_code(url: str, expected_state: str) -> str | None:
    """Inspect a redirect target without ever opening a loopback callback."""

    code = _callback_code(url, expected_state)
    if code:
        return code
    if _is_expected_callback(url):
        raise AuthCodeMintError("oauth callback missing code")
    if _is_loopback_url(url):
        raise AuthCodeMintError("oauth callback redirect URI mismatch")
    return None


def _follow_consent_redirects(
    session: Any,
    response: Any,
    *,
    request_url: str,
    expected_state: str,
    timeout: float,
    deadline: float,
    cancel: Callable[[], bool] | None,
    max_hops: int = MAX_REDIRECT_HOPS,
) -> tuple[str | None, str]:
    """Follow only remote redirects and return ``(code, response_body)``.

    The configured OAuth callback is intentionally parsed from redirect
    metadata instead of requested; no local callback listener is required.
    """

    current_response = response
    current_request_url = request_url
    for hop in range(max(0, int(max_hops)) + 1):
        _check_active(cancel, deadline)
        response_url = str(getattr(current_response, "url", "") or current_request_url)
        code = _callback_code(response_url, expected_state)
        if code:
            return code, str(getattr(current_response, "text", "") or "")

        body = str(getattr(current_response, "text", "") or "")
        body_code = _parse_consent_code(body)
        if body_code:
            return body_code, body

        next_url = ""
        for raw_target in _redirect_candidates(current_response, body):
            target = urllib.parse.urljoin(response_url, raw_target)
            code = _callback_target_code(target, expected_state)
            if code:
                return code, body
            if _is_trusted_oauth_redirect(target):
                next_url = target
                break
        if not next_url:
            return None, body
        if hop >= max_hops:
            raise AuthCodeMintError(
                f"consent redirect exceeded {max_hops} hops"
            )

        _check_active(cancel, deadline)
        try:
            current_response = session.get(
                next_url,
                impersonate="chrome",
                timeout=_request_timeout(timeout, deadline),
                allow_redirects=False,
            )
        except Exception as exc:  # noqa: BLE001
            raise AuthCodeMintError(
                f"consent redirect exception: {_redact_error(exc)}"
            ) from exc
        current_request_url = next_url

    raise AuthCodeMintError(f"consent redirect exceeded {max_hops} hops")


def _extract_next_action_ids(html: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def _add(val: str) -> None:
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        found.append(v)

    text = html or ""
    for m in _CREATE_SERVER_REF_RE.finditer(text):
        _add(m.group(1))
    for m in _CALL_SERVER_RE.finditer(text):
        _add(m.group(1))
    for m in _NEXT_ACTION_RE.finditer(text):
        _add(m.group(1))
    if NEXT_ACTION_ID and NEXT_ACTION_ID.lower() not in seen:
        found.append(NEXT_ACTION_ID.lower())
    return found


def _discover_action_ids_from_js(
    session: Any,
    html: str,
    *,
    base_url: str = "https://accounts.x.ai",
    log: LogFn | None = None,
    timeout: float = 15.0,
    deadline: float | None = None,
    cancel: Callable[[], bool] | None = None,
    max_chunks: int = 8,
) -> list[str]:
    log = log or _noop
    found: list[str] = []
    seen: set[str] = set()
    priority: list[str] = []

    def _add(val: str, prefer: bool = False) -> None:
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        if prefer:
            priority.append(v)
        else:
            found.append(v)

    srcs = _SCRIPT_SRC_RE.findall(html or "")
    scored: list[tuple[int, str]] = []
    for src in srcs:
        low = src.lower()
        if "chunk" not in low and "/_next/" not in low:
            continue
        score = 0
        if any(k in low for k in ("consent", "oauth", "auth", "login", "sign")):
            score += 5
        scored.append((score, src))
    scored.sort(key=lambda x: (-x[0], x[1]))

    fetched = 0
    for score, src in scored:
        if fetched >= max(0, int(max_chunks)):
            break
        if deadline is not None:
            _check_active(cancel, deadline)
        full = (
            src
            if src.startswith("http")
            else urllib.parse.urljoin(base_url.rstrip("/") + "/", src.lstrip("/"))
        )
        try:
            request_timeout = (
                _request_timeout(timeout, deadline)
                if deadline is not None
                else timeout
            )
            resp = session.get(full, impersonate="chrome", timeout=request_timeout)
            text = str(resp.text or "")
        except AuthCodeMintError:
            raise
        except Exception:
            continue
        fetched += 1
        prefer = score > 0 or ("consent" in text.lower() and "oauth" in text.lower())
        if "createServerReference" in text or "callServer" in text:
            prefer = True
        for m in _CREATE_SERVER_REF_RE.finditer(text):
            _add(m.group(1), prefer=prefer)
        for m in _CALL_SERVER_RE.finditer(text):
            _add(m.group(1), prefer=prefer)

    for aid in _extract_next_action_ids(html):
        _add(aid, prefer=False)

    ordered = priority + [x for x in found if x not in priority]
    log(f"auth-code: JS chunks Next-Action {len(ordered)} (scanned {fetched} scripts)")
    return ordered


def _mint_with_sso_auth_code_session(
    *,
    session: Any,
    deadline: float,
    sso_cookie: str,
    email: str = "",
    timeout: float = 15.0,
    require_referrer: bool = True,
    required_referrer: str | None = None,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Exchange SSO for OIDC tokens via auth-code + PKCE with referrer=grok-build.

    Returns a token dict compatible with device-mint consumers:
    access_token, refresh_token, id_token?, expires_in, token_type, mint_method.
    """
    global _working_next_action_id

    log = log or _noop
    sso = (sso_cookie or "").strip()
    if sso.startswith("sso="):
        sso = sso[4:].strip()
    if not sso:
        raise AuthCodeMintError("empty sso cookie")
    _check_active(cancel, deadline)

    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai"):
        session.cookies.set("sso", sso, domain=domain)
        session.cookies.set("sso-rw", sso, domain=domain)

    try:
        r = session.get(
            "https://accounts.x.ai/",
            impersonate="chrome",
            timeout=_request_timeout(timeout, deadline),
        )
    except Exception as exc:  # noqa: BLE001
        raise AuthCodeMintError(f"sso validate network: {_redact_error(exc)}") from exc
    if "sign-in" in str(r.url) or "sign-up" in str(r.url):
        raise AuthCodeMintError("sso invalid (redirected to sign-in/up)")
    log(f"auth-code: sso valid email={email or '?'}")

    verifier, challenge, state, nonce = _gen_pkce()
    log(f"auth-code: Authorization Code Flow referrer={GROK_REFERRER} plan={GROK_PLAN}")
    authorize_params = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "plan": GROK_PLAN,
            "redirect_uri": DEFAULT_REDIRECT_URI,
            "referrer": GROK_REFERRER,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
        }
    )
    authorize_url = f"{OIDC_ISSUER}/oauth2/authorize?{authorize_params}"

    def _open_consent(discover_actions: bool = False):
        _check_active(cancel, deadline)
        current_url = authorize_url
        resp = None
        url = current_url
        for _ in range(MAX_REDIRECT_HOPS):
            _check_active(cancel, deadline)
            direct_code = _callback_target_code(current_url, state)
            if direct_code:
                return resp, current_url, [], direct_code
            try:
                resp = session.get(
                    current_url,
                    impersonate="chrome",
                    timeout=_request_timeout(timeout, deadline),
                    allow_redirects=False,
                )
            except Exception as exc:  # noqa: BLE001
                raise AuthCodeMintError(
                    f"authorize exception: {_redact_error(exc)}"
                ) from exc
            url = str(resp.url or current_url)
            direct_code = _callback_code(url, state)
            if direct_code:
                return resp, url, [], direct_code
            headers = getattr(resp, "headers", {}) or {}
            location = str(headers.get("location", "") or "")
            status_code = int(getattr(resp, "status_code", 0) or 0)
            if 300 <= status_code < 400 and location:
                current_url = urllib.parse.urljoin(url, location)
                direct_code = _callback_target_code(current_url, state)
                if direct_code:
                    return resp, current_url, [], direct_code
                continue
            break
        if resp is None:
            raise AuthCodeMintError("authorize returned no response")
        if "sign-in" in url or "sign-up" in url:
            raise AuthCodeMintError("sso invalid during authorize")
        if "/oauth2/consent" not in url:
            raise AuthCodeMintError(
                f"authorize did not reach consent: {_redact_error(url)[:200]}"
            )
        html = str(resp.text or "")
        base = "https://accounts.x.ai"
        if "auth.x.ai" in url and "accounts.x.ai" not in url:
            base = "https://auth.x.ai"
        if discover_actions:
            action_ids = _discover_action_ids_from_js(
                session,
                html,
                base_url=base,
                log=log,
                timeout=timeout,
                deadline=deadline,
                cancel=cancel,
                max_chunks=8,
            )
        else:
            action_ids: list[str] = []
            cached = str(_working_next_action_id or "").strip().lower()
            if cached:
                action_ids.append(cached)
            for action_id in _extract_next_action_ids(html):
                if action_id not in action_ids:
                    action_ids.append(action_id)
            log(f"auth-code: consent fast-path Next-Action candidates={len(action_ids)}")
        return resp, url, action_ids, None

    _, final_url, action_ids, code = _open_consent()
    if not action_ids:
        action_ids = [NEXT_ACTION_ID]
        log(f"auth-code: using fallback Next-Action {NEXT_ACTION_ID[:12]}...")
    else:
        log(
            f"auth-code: consent Next-Action candidates={len(action_ids)} "
            f"first={action_ids[0][:12]}..."
        )

    consent_payload = json.dumps(
        [
            {
                "action": "allow",
                "clientId": CLIENT_ID,
                "redirectUri": DEFAULT_REDIRECT_URI,
                "scope": SCOPES,
                "state": state,
                "codeChallenge": challenge,
                "codeChallengeMethod": "S256",
                "nonce": nonce,
                "principalType": "User",
                "principalId": "",
                "referrer": GROK_REFERRER,
            }
        ]
    )

    last_err = ""
    tried: set[str] = set()
    for round_i in range(2):
        if code:
            break
        _check_active(cancel, deadline)
        if round_i > 0:
            log("auth-code: consent retry with JS Next-Action discovery")
            _, final_url, action_ids, code = _open_consent(discover_actions=True)
            if code:
                break
            if not action_ids:
                action_ids = [NEXT_ACTION_ID]

        for action_id in action_ids:
            _check_active(cancel, deadline)
            if len(tried) >= 5:
                break
            if action_id in tried:
                continue
            tried.add(action_id)
            try:
                consent_origin = _origin_for_url(final_url)
                resp = session.post(
                    final_url,
                    data=consent_payload,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Accept": "text/x-component",
                        "Origin": consent_origin,
                        "Referer": final_url,
                        "Next-Action": action_id,
                    },
                    impersonate="chrome",
                    timeout=_request_timeout(timeout, deadline),
                    allow_redirects=False,
                )
            except Exception as exc:  # noqa: BLE001
                last_err = f"consent exception: {_redact_error(exc)}"
                log(f"auth-code: {last_err}")
                continue
            try:
                code, body = _follow_consent_redirects(
                    session,
                    resp,
                    request_url=final_url,
                    expected_state=state,
                    timeout=timeout,
                    deadline=deadline,
                    cancel=cancel,
                )
            except AuthCodeMintError:
                raise
            except Exception as exc:  # noqa: BLE001
                last_err = f"consent redirect exception: {_redact_error(exc)}"
                log(f"auth-code: {last_err}")
                continue
            if code:
                _working_next_action_id = action_id
                log(f"auth-code: Next-Action {action_id[:12]}... redirected with code")
                break
            if resp.status_code == 404 or "server action not found" in body.lower():
                last_err = f"consent HTTP {resp.status_code}: {_redact_error(body)[:160]}"
                log(f"auth-code: Next-Action {action_id[:12]}... invalid")
                continue
            if resp.status_code < 200 or resp.status_code >= 300:
                last_err = f"consent HTTP {resp.status_code}: {_redact_error(body)[:200]}"
                log(f"auth-code: {last_err}")
                continue
            last_err = f"consent no code: {_redact_error(body)[:180]}"
            log(f"auth-code: Next-Action {action_id[:12]}... not allow action")
        if code:
            break

    if not code:
        raise AuthCodeMintError(
            f"consent failed after {len(tried)} Next-Action tries: {last_err}"
        )
    log("auth-code: consent OK")

    token_data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DEFAULT_REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        }
    )
    _check_active(cancel, deadline)
    try:
        resp = session.post(
            f"{OIDC_ISSUER}/oauth2/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": GROK_TOKEN_UA,
                "X-Grok-Client-Version": GROK_VERSION,
                "Accept": "*/*",
            },
            impersonate="chrome",
            timeout=_request_timeout(timeout, deadline),
        )
    except Exception as exc:  # noqa: BLE001
        raise AuthCodeMintError(
            f"token exchange exception: {_redact_error(exc)}"
        ) from exc
    if resp.status_code < 200 or resp.status_code >= 300:
        raise AuthCodeMintError(
            f"token HTTP {resp.status_code}: {_redact_error(resp.text)[:200]}"
        )
    try:
        token = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise AuthCodeMintError(
            f"token non-JSON: {_redact_error(resp.text)[:200]}"
        ) from exc
    if not isinstance(token, dict) or not token.get("access_token"):
        raise AuthCodeMintError("token missing access_token")
    if not token.get("refresh_token"):
        raise AuthCodeMintError("token missing refresh_token (CPA cannot renew)")
    if not token.get("expires_in"):
        token["expires_in"] = 21600
    if not token.get("token_type"):
        token["token_type"] = "Bearer"

    required_ref = (
        str(required_referrer).strip()
        if required_referrer is not None
        else (GROK_REFERRER if require_referrer else "")
    )
    ref = access_token_referrer(str(token["access_token"]))
    if required_ref and ref != required_ref:
        msg = f"access_token referrer={ref!r} (expected {required_ref!r})"
        if required_ref:
            raise AuthCodeMintError(msg)
    elif not required_ref and ref not in EXPECTED_REFERRERS:
        log(
            f"auth-code: WARN access_token referrer={ref!r} "
            "(referrer policy disabled)"
        )
    else:
        log(f"auth-code: access_token referrer={ref!r} OK")
    log(
        f"auth-code: SUCCESS expires_in={token.get('expires_in')}s"
        + (" +refresh" if token.get("refresh_token") else "")
    )

    out = dict(token)
    out["mint_method"] = "auth_code"
    out["referrer"] = ref
    return out


def mint_with_sso_auth_code(
    *,
    sso_cookie: str,
    email: str = "",
    proxy: str | None = None,
    timeout: float = 15.0,
    total_timeout_sec: float = 90.0,
    require_referrer: bool = True,
    required_referrer: str | None = None,
    log: LogFn | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Exchange SSO for OIDC tokens with a bounded total runtime."""

    resolved = resolve_proxy(proxy)
    session = cf_requests.Session()
    if resolved:
        session.proxies = {"http": resolved, "https": resolved}
    deadline = time.monotonic() + max(0.01, float(total_timeout_sec))
    try:
        return _mint_with_sso_auth_code_session(
            session=session,
            deadline=deadline,
            sso_cookie=sso_cookie,
            email=email,
            timeout=timeout,
            require_referrer=require_referrer,
            required_referrer=required_referrer,
            log=log,
            cancel=cancel,
        )
    finally:
        try:
            session.close()
        except Exception:
            pass
