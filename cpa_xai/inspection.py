"""Post-registration xAI/Grok access health inspection.

The implementation mirrors the lightweight probe and classification rules in
``ywddd/grok-inspection`` while using a Chrome-impersonating HTTP transport. A
single call to :func:`inspect_access_token` performs model discovery, a
``/responses`` request, and (for the statuses used by the upstream inspector)
the ``/chat/completions`` fallback.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from curl_cffi import requests as cf_requests

from .proxyutil import resolve_proxy
from .schema import DEFAULT_BASE_URL

PREFERRED_MODELS = ("grok-4.5-build-free", "grok-4.5", "grok-4", "grok-3-mini")
_FALLBACK_STATUSES = {401, 402, 403, 429}
INSPECTION_CLIENT_HEADERS = {
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-grok-client-version": "0.2.93",
    "User-Agent": "xai-grok-workspace/0.2.93",
}


def _as_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def extract_error(
    body: str | bytes | Mapping[str, Any] | None,
    *,
    raw_fallback: str | bytes | None = None,
) -> dict[str, str]:
    """Extract ``code`` and human-readable ``message`` from an API error."""

    if isinstance(body, Mapping):
        data: Mapping[str, Any] = body
        raw = ""
    else:
        raw = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
        raw = raw.strip()
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {}
        data = parsed if isinstance(parsed, Mapping) else {}

    code = _as_string(data.get("code"))
    message = ""
    nested = data.get("error")
    if isinstance(nested, Mapping):
        if not code:
            code = _as_string(nested.get("code"))
        message = _as_string(nested.get("message")) or _as_string(nested.get("error"))
    elif isinstance(nested, str):
        message = nested.strip()
    if not message:
        message = _as_string(data.get("message"))
    if not message:
        message = _as_string(data.get("detail")) or _as_string(data.get("title"))
    if not message:
        errors = data.get("errors")
        if isinstance(errors, list):
            message = "; ".join(
                value
                for value in (_as_string(item) for item in errors)
                if value
            )
        elif isinstance(errors, Mapping):
            message = "; ".join(
                value
                for value in (_as_string(item) for item in errors.values())
                if value
            )
        else:
            message = _as_string(errors)
    if not message and raw_fallback:
        message = (
            raw_fallback.decode("utf-8", errors="replace")
            if isinstance(raw_fallback, bytes)
            else str(raw_fallback)
        ).strip()
    if not message:
        message = raw
    return {"code": code, "message": message}


def pick_model(body: Mapping[str, Any] | str | bytes | None) -> str:
    """Select the same preferred model order as grok-inspection."""

    if isinstance(body, Mapping):
        data = body
    else:
        raw = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {}
        data = parsed if isinstance(parsed, Mapping) else {}
    rows = data.get("data")
    ids: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, Mapping):
                ident = _as_string(row.get("id")) or _as_string(row.get("model"))
                if ident:
                    ids.append(ident)
    for preferred in PREFERRED_MODELS:
        if preferred in ids:
            return preferred
    return ids[0] if ids else "grok-4.5"


def _contains_any(text: str, *needles: str) -> bool:
    value = (text or "").strip().lower()
    return any(needle and needle.lower() in value for needle in needles)


def classify_probe(
    status: int | Mapping[str, Any] = 0,
    *,
    code: str = "",
    error: str = "",
    request_error: str = "",
    disabled: bool = False,
) -> dict[str, str]:
    """Classify one chat probe using grok-inspection's precedence rules."""

    # Accept a result mapping as a convenience for callers porting the Go
    # inspector's ``classifyInput`` structure.
    if isinstance(status, Mapping):
        item = status
        status = int(item.get("status", item.get("chat_status", 0)) or 0)
        code = code or _as_string(item.get("code", item.get("chat_code")))
        error = error or _as_string(item.get("error", item.get("chat_error")))
        request_error = request_error or _as_string(item.get("request_error"))
        disabled = bool(item.get("disabled", disabled))

    blob = f"{code} {error}".lower()
    auth_evidence = _contains_any(
        blob,
        "token is expired",
        "token has been invalidated",
        "invalid_grant",
        "unauthorized",
    )
    quota_evidence = _contains_any(
        blob,
        "free-usage-exhausted",
        "included free usage",
        "usage_limit_reached",
        "quota exhausted",
        "limit reached",
    )
    permission_evidence = _contains_any(
        blob,
        "permission-denied",
        "chat endpoint is denied",
        "deactivated",
        "suspended",
        "banned",
    )
    if status == 401 or auth_evidence:
        return {
            "classification": "reauth",
            "action": "delete",
            "reason": "认证已过期或失效",
            "confidence": "confirmed",
        }
    if status == 429 or quota_evidence:
        return {
            "classification": "quota_exhausted",
            "action": "keep" if disabled else "disable",
            "reason": "额度已用尽",
            "confidence": "confirmed" if quota_evidence else "status_only",
        }
    if status in {402, 403} or permission_evidence:
        reason = "对话权限被拒绝" if permission_evidence else "接口返回禁止访问"
        if status:
            reason += f" (HTTP {status})"
        return {
            "classification": "permission_denied" if permission_evidence else "forbidden_unknown",
            "action": (
                "keep"
                if disabled or not permission_evidence
                else "disable"
            ),
            "reason": reason,
            "confidence": "confirmed" if permission_evidence else "inconclusive",
        }
    if status == 404 or _contains_any(blob, "not-found", "does not exist", "no access to it"):
        return {"classification": "model_unavailable", "action": "keep", "reason": "测试模型不可用", "confidence": "confirmed"}
    if 200 <= status < 300:
        return {"classification": "healthy", "action": "enable" if disabled else "keep", "reason": "对话测试成功", "confidence": "confirmed"}
    if request_error or status > 0:
        reason = request_error.strip() or (f"探测失败 (HTTP {status})" if status else "探测失败")
        return {"classification": "probe_error", "action": "keep", "reason": reason, "confidence": "inconclusive"}
    return {"classification": "unknown", "action": "keep", "reason": "无法可靠分类", "confidence": "inconclusive"}


def _curl_session(proxy: str | None = None):
    session = cf_requests.Session()
    resolved = resolve_proxy(proxy)
    if resolved:
        session.proxies = {"http": resolved, "https": resolved}
    return session


def _request_json(
    client: Any,
    method: str,
    url: str,
    *,
    token: str,
    payload: Mapping[str, Any] | None,
    timeout: float,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **INSPECTION_CLIENT_HEADERS,
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    started = time.monotonic()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        if hasattr(client, "open"):
            response_cm = client.open(req, timeout=timeout)
        else:
            response = client.request(
                method,
                url,
                headers=headers,
                json=dict(payload) if payload is not None else None,
                timeout=timeout,
                impersonate="chrome",
            )
            raw = str(getattr(response, "text", "") or "")
            try:
                body: Any = json.loads(raw) if raw else {}
            except Exception:
                body = {}
            response_headers = getattr(response, "headers", {}) or {}
            return {
                "status": int(getattr(response, "status_code", 0) or 0),
                "body": body,
                "raw": raw,
                "request_error": "",
                "content_type": str(response_headers.get("content-type", "") or ""),
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
            }
        with response_cm as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(raw) if raw else {}
            except Exception:
                body = {}
            headers_obj = getattr(response, "headers", {}) or {}
            return {
                "status": int(getattr(response, "status", 200) or 200),
                "body": body,
                "raw": raw,
                "request_error": "",
                "content_type": str(headers_obj.get("content-type", "") or "") if hasattr(headers_obj, "get") else "",
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        headers_obj = getattr(exc, "headers", {}) or {}
        return {
            "status": int(exc.code),
            "body": body,
            "raw": raw,
            "request_error": "",
            "content_type": str(headers_obj.get("content-type", "") or "") if hasattr(headers_obj, "get") else "",
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": 0,
            "body": {},
            "raw": "",
            "request_error": str(exc),
            "content_type": "",
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
        }


def inspect_access_token(
    access_token: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 30.0,
    proxy: str | None = None,
    opener: Any | None = None,
) -> dict[str, Any]:
    """Inspect one access token and return a stable, JSON-serializable result."""

    if not (access_token or "").strip():
        return {
            "ok": False,
            "classification": "unknown",
            "action": "keep",
            "http_status": 0,
            "model": "",
            "error_code": "",
            "error_message": "access_token is required",
            "primary_endpoint": "",
        }
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    client = opener or _curl_session(proxy)
    result: dict[str, Any] = {
        "ok": False,
        "classification": "unknown",
        "action": "keep",
        "http_status": 0,
        "status": 0,
        "model": "",
        "error_code": "",
        "error_message": "",
        "primary_endpoint": f"{base}/responses",
    }

    models = _request_json(client, "GET", f"{base}/models", token=access_token, payload=None, timeout=timeout)
    result["models_status"] = models["status"]
    model_error = extract_error(
        models.get("body") or models.get("raw"),
        raw_fallback=models.get("raw"),
    )
    result["models"] = models.get("body")
    result["models_error_code"] = model_error["code"]
    result["models_error_message"] = model_error["message"] or models["request_error"]
    result["models_content_type"] = models.get("content_type", "")
    result["models_duration_ms"] = models.get("duration_ms", 0)
    result["models_raw_snippet"] = str(models.get("raw") or "")[:500]
    if 200 <= models["status"] < 300:
        model = pick_model(models.get("body"))
    else:
        # Match grok-inspection: model discovery is advisory. Even when it
        # fails, probe the real chat endpoint with the default model.
        model = "grok-4.5"
    result["model"] = model
    responses = _request_json(
        client,
        "POST",
        f"{base}/responses",
        token=access_token,
        payload={"model": model, "stream": False, "input": "ping"},
        timeout=timeout,
    )
    result["responses"] = responses.get("body")
    main_error = extract_error(
        responses.get("body") or responses.get("raw"),
        raw_fallback=responses.get("raw"),
    )
    main_status = responses["status"]
    result.update(
        http_status=main_status,
        status=main_status,
        error_code=main_error["code"],
        error_message=main_error["message"] or responses["request_error"],
        responses_content_type=responses.get("content_type", ""),
        responses_duration_ms=responses.get("duration_ms", 0),
        responses_raw_snippet=str(responses.get("raw") or "")[:500],
    )

    main_class = classify_probe(main_status, code=main_error["code"], error=main_error["message"], request_error=responses["request_error"])
    fallback: dict[str, Any] | None = None
    if main_status in _FALLBACK_STATUSES:
        fallback = _request_json(
            client,
            "POST",
            f"{base}/chat/completions",
            token=access_token,
            payload={"model": model, "stream": False, "messages": [{"role": "user", "content": "ping"}]},
            timeout=timeout,
        )
        result["fallback"] = fallback.get("body")
        result["fallback_status"] = fallback["status"]
        result["fallback_endpoint"] = f"{base}/chat/completions"
        fallback_error = extract_error(
            fallback.get("body") or fallback.get("raw"),
            raw_fallback=fallback.get("raw"),
        )
        result["fallback_error_code"] = fallback_error["code"]
        result["fallback_error_message"] = fallback_error["message"] or fallback["request_error"]
        result["fallback_content_type"] = fallback.get("content_type", "")
        result["fallback_duration_ms"] = fallback.get("duration_ms", 0)
        result["fallback_raw_snippet"] = str(fallback.get("raw") or "")[:500]
        # Main endpoint's auth/quota/permission classification is authoritative.
        # For other transient failures, use a successful fallback if available.
        if main_class["classification"] not in {
            "reauth",
            "quota_exhausted",
            "permission_denied",
            "forbidden_unknown",
        }:
            fallback_class = classify_probe(fallback["status"], code=fallback_error["code"], error=fallback_error["message"], request_error=fallback["request_error"])
            if fallback_class["classification"] == "healthy" or main_class["classification"] in {"probe_error", "unknown"}:
                main_class = fallback_class
                result.update(http_status=fallback["status"], status=fallback["status"], error_code=fallback_error["code"], error_message=fallback_error["message"] or fallback["request_error"])
        elif (
            main_class["classification"]
            in {"permission_denied", "forbidden_unknown"}
            and 200 <= fallback["status"] < 300
        ):
            main_class = {
                "classification": "endpoint_inconsistent",
                "action": "keep",
                "reason": "主 /responses 拒绝，但备用 /chat/completions 成功",
                "confidence": "inconclusive",
            }

    result.update(main_class)
    result["ok"] = result["classification"] == "healthy"
    return result


def aggregate_health_attempts(
    attempts: list[Mapping[str, Any]],
    *,
    reject_inconclusive: bool = True,
) -> dict[str, Any]:
    """Aggregate repeated post-registration probes into one gate decision."""
    rows = [dict(item) for item in attempts if isinstance(item, Mapping)]
    if not rows:
        return {
            "ok": False,
            "classification": "unknown",
            "confidence": "inconclusive",
            "reason": "没有可用健康探测结果",
            "reject_candidate": False,
            "reject_reason": "",
            "attempts": [],
        }

    for row in rows:
        if row.get("classification") == "healthy":
            return {
                **row,
                "ok": True,
                "reject_candidate": False,
                "reject_reason": "",
                "attempts": rows,
            }

    classes = [str(row.get("classification") or "unknown") for row in rows]
    repeated = len(rows) >= 2
    confirmed_permission = repeated and all(
        row.get("classification") == "permission_denied"
        and row.get("confidence") == "confirmed"
        for row in rows
    )
    if confirmed_permission:
        final = dict(rows[-1])
        final.update(
            ok=False,
            classification="permission_denied",
            confidence="confirmed",
            reason="连续探测确认对话权限被拒绝",
            reject_candidate=True,
            reject_reason="permission_denied",
            attempts=rows,
        )
        return final

    persistent_access_failure = repeated and all(
        value in {
            "permission_denied",
            "forbidden_unknown",
            "endpoint_inconsistent",
        }
        for value in classes
    )
    if persistent_access_failure and any(
        value == "endpoint_inconsistent" for value in classes
    ):
        classification = "endpoint_inconsistent"
    elif persistent_access_failure:
        classification = "forbidden_unknown"
    elif all(value == "reauth" for value in classes):
        classification = "reauth"
    elif any(value == "quota_exhausted" for value in classes):
        classification = "quota_exhausted"
    elif any(value == "model_unavailable" for value in classes):
        classification = "model_unavailable"
    elif any(value == "probe_error" for value in classes):
        classification = "probe_error"
    else:
        classification = classes[-1]

    final = dict(rows[-1])
    reject = classification == "reauth" or bool(
        reject_inconclusive
        and classification in {"forbidden_unknown", "endpoint_inconsistent"}
    )
    confidence = (
        "confirmed"
        if classification == "reauth" and all(value == "reauth" for value in classes)
        else "inconclusive"
    )
    final.update(
        ok=False,
        classification=classification,
        confidence=confidence,
        reason={
            "forbidden_unknown": "连续探测仍返回无法确认原因的禁止访问",
            "endpoint_inconsistent": "主接口与备用接口连续返回不一致结果",
            "reauth": "连续探测确认认证已过期或失效",
        }.get(classification, str(final.get("reason") or "健康探测未通过")),
        reject_candidate=reject,
        reject_reason=classification if reject else "",
        attempts=rows,
    )
    return final


# Friendly aliases for callers that use the probe terminology.
inspect_token = inspect_access_token
classify_result = classify_probe


__all__ = [
    "PREFERRED_MODELS",
    "INSPECTION_CLIENT_HEADERS",
    "classify_probe",
    "classify_result",
    "extract_error",
    "aggregate_health_attempts",
    "inspect_access_token",
    "inspect_token",
    "pick_model",
]
