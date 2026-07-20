"""CLI wrapper for grok_register_ttk — multi-thread register + async CPA mint pipeline.

Architecture:
  Register workers (R)  →  accounts_cli + mint_queue
  Mint workers (M)      →  cpa_auths/xai-*.json + optional hotload

Browser lifecycle:
  - Default: quit the register Chromium after every account
  - Optional --browser-reuse keeps one Chromium per register worker
  - Reused browsers are fully recycled every N accounts or on error
  - Register browser released BEFORE mint (mint always standalone Chromium)
  - Peak browsers ≈ R + M (not 2×R)
"""
from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
import traceback
from typing import Any

# 强制走本目录的 grok_register_ttk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grok_register_ttk as reg  # noqa: E402


# Linux 适配: DrissionPage 默认找 'chrome', 我们装的是 chromium
# 保留原版 slim flags + proxy，再补 chromium 路径与 turnstilePatch。
_orig_create_browser_options = reg.create_browser_options


def _patched_create_browser_options():
    # Prefer original factory (proxy + CHROMIUM_SLIM_FLAGS + extension)
    try:
        opts = _orig_create_browser_options()
    except Exception:
        from DrissionPage import ChromiumOptions

        opts = ChromiumOptions()
        opts.auto_port()
        opts.set_timeouts(base=1)
        for flag in getattr(reg, "CHROMIUM_SLIM_FLAGS", ()) or ():
            try:
                opts.set_argument(flag)
            except Exception:
                pass

    try:
        opts.auto_port()
    except Exception:
        pass
    try:
        opts.set_timeouts(base=1)
    except Exception:
        pass

    for cand in (
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ):
        if os.path.isfile(cand):
            try:
                opts.set_browser_path(cand)
            except Exception:
                pass
            break

    ext_path = os.path.join(os.path.dirname(os.path.abspath(reg.__file__)), "turnstilePatch")
    if os.path.isdir(ext_path):
        try:
            opts.add_extension(ext_path)
        except Exception:
            pass
    return opts


reg.create_browser_options = _patched_create_browser_options


# ── 线程安全日志 ──

_log_queue: queue.Queue = queue.Queue()


def _log_writer():
    while True:
        msg = _log_queue.get()
        if msg is None:
            break
        print(msg, flush=True)


def log(worker_id: int | str, msg: str) -> None:
    _log_queue.put(f"[{time.strftime('%H:%M:%S')}] [W{worker_id}] {msg}")


# ── 统计 ──

_stats_lock = threading.Lock()
_stats = {
    "reg_success": 0,
    "reg_fail": 0,
    "mint_success": 0,
    "mint_fail": 0,
    "mint_skip": 0,
    "health_rejected": 0,
    "health_unknown": 0,
    "activation_failed": 0,
}


def _inc(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


# forever 任务索引
_next_idx_lock = threading.Lock()
_next_idx = [1]

# mint 队列结束哨兵
_MINT_STOP = object()
_TASK_STOP = object()
_REGISTER_STOP = threading.Event()
_REGISTER_CAPACITY_STOP = threading.Event()
_SCHEDULER_DONE = threading.Event()
_accounts_lock = threading.Lock()


def _rotation_enabled_config(config: dict | None) -> bool:
    value = (config or {}).get("proxy_rotation_enabled", False)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _prepare_rotation_manager(config: dict, log_callback=None):
    """Validate rotation before workers can consume an email and reset batch state."""
    if not _rotation_enabled_config(config):
        return None
    import proxy_rotation as proxy_rot

    validator = getattr(proxy_rot, "validate_rotation_config", None)
    if callable(validator):
        validator(config)
    manager = proxy_rot.get_manager(config, log=log_callback)
    reset_breaker = getattr(manager, "reset_batch_breaker", None)
    if callable(reset_breaker):
        reset_breaker()
    return manager


def _rotation_should_stop_batch(manager) -> bool:
    if manager is None:
        return False
    for name in ("should_stop_batch", "batch_breaker_tripped"):
        checker = getattr(manager, name, None)
        if callable(checker):
            try:
                if checker():
                    return True
            except Exception:
                continue
    return False


def _release_rotation_lease(
    worker_id: int | str,
    manager,
    lease,
    status: str,
    mint_result: dict[str, Any] | None = None,
) -> bool:
    """Release a lease and return whether the batch breaker is now open."""
    if manager is None or lease is None:
        return False
    try:
        import proxy_rotation as proxy_rot

        outcome = proxy_rot.map_registration_outcome(status, mint_result)
        manager.release(lease, outcome)
    except Exception as exc:
        log(worker_id, f"[proxy-rot] release failed; stop batch: {exc}")
        _REGISTER_STOP.set()
        return True
    if _rotation_should_stop_batch(manager):
        log(
            worker_id,
            "[proxy-rot] 连续出口访问拒绝已触发批次熔断；停止派发剩余任务",
        )
        _REGISTER_STOP.set()
        return True
    return False


def resolve_mint_workers(
    *,
    cli_value: int,
    threads: int,
    config: dict,
    inline_mint: bool,
) -> int:
    """Resolve mint worker count.

    Priority: --inline-mint > CLI --mint-workers (>=0) > config cpa_mint_workers > auto.
    auto (-1): min(threads, 4) when CPA export enabled, else 0.
    0: inline mint on register threads.
    """
    if inline_mint:
        return 0
    if cli_value >= 0:
        return max(0, min(int(cli_value), 10))
    cfg_v = config.get("cpa_mint_workers", -1)
    try:
        cfg_v = int(cfg_v)
    except Exception:
        cfg_v = -1
    if cfg_v >= 0:
        return max(0, min(cfg_v, 10))
    # auto
    if config.get("cpa_export_enabled", True) or config.get("registration_health_check_enabled", True):
        return max(1, min(int(threads), 4))
    return 0


def resolve_mint_queue_max(config: dict, mint_workers: int, cli_value: int | None = None) -> int:
    if cli_value is not None and cli_value >= 0:
        return int(cli_value)
    try:
        v = int(config.get("cpa_mint_queue_max", 0) or 0)
    except Exception:
        v = 0
    if v > 0:
        return v
    # default backpressure: 2 × mint workers (0 if no mint pool)
    return max(0, mint_workers * 2) if mint_workers > 0 else 0


class DummyStop:
    def __call__(self) -> bool:
        return _REGISTER_STOP.is_set()


def _is_managed_mail_provider() -> bool:
    try:
        provider = reg.get_email_provider()
    except Exception:
        provider = (getattr(reg, "config", {}) or {}).get("email_provider", "")
    return str(provider or "").strip().lower() in {
        "hotmail", "outlook", "outlookmail", "microsoft", "custommail", "custom_mail"
    }


def _mark_email_stage_error(email: str, reason: str) -> None:
    """Persist failed Hotmail/Outlook aliases so the next run does not reuse them."""
    if not email or not _is_managed_mail_provider():
        return
    try:
        reg.mark_error(email, reason=str(reason)[:120])
    except Exception:
        pass


def _ensure_browser(worker_id: int, force_recycle: bool = False):
    """Start browser if missing; optional full recycle."""
    if force_recycle:
        try:
            reg.stop_browser()
        except Exception:
            pass
    if reg.TabPool.get_browser() is None:
        reg.start_browser(log_callback=lambda m: log(worker_id, m))


def register_one(
    worker_id: int,
    idx: int,
    total: int,
) -> dict | None:
    """Create one candidate account without committing it to any local pool.

    Returns dict(email, sso, profile) or None.
    """
    email = ""
    dev_token = ""
    try:
        max_mail_retry = max(1, int((getattr(reg, "config", {}) or {}).get("mail_retry_count", 3) or 3))
    except Exception:
        max_mail_retry = 3
    cancel = DummyStop()

    try:
        _ensure_browser(worker_id, force_recycle=False)
    except Exception as exc:
        log(worker_id, f"! 浏览器启动失败: {exc}")
        return None

    for mail_try in range(1, max_mail_retry + 1):
        email = ""
        dev_token = ""
        try:
            log(worker_id, f"--- 第 {idx}/{total} 个账号, 邮箱尝试 {mail_try}/{max_mail_retry} ---")
            log(worker_id, "1. 打开注册页")
            reg.open_signup_page(log_callback=lambda m: log(worker_id, m), cancel_callback=cancel)
            log(worker_id, "2. 创建邮箱并提交")
            email, dev_token = reg.fill_email_and_submit(
                log_callback=lambda m: log(worker_id, m), cancel_callback=cancel
            )
            log(worker_id, f"邮箱: {email}")
            log(worker_id, "3. 拉取验证码")
            code = reg.fill_code_and_submit(
                email,
                dev_token,
                log_callback=lambda m: log(worker_id, m),
                cancel_callback=cancel,
            )
            log(worker_id, f"验证码: {code}")
            break
        except reg.CustomMailCapacityExhausted as exc:
            _REGISTER_CAPACITY_STOP.set()
            log(worker_id, f"! {exc}；停止派发剩余注册任务")
            return None
        except Exception as exc:
            msg = str(exc)
            if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                log(worker_id, f"! 本邮箱未取到验证码，换邮箱重试: {msg}")
                _mark_email_stage_error(email, msg)
                try:
                    reg.restart_browser(log_callback=lambda m: log(worker_id, m))
                except Exception:
                    pass
                reg.sleep_with_cancel(1, cancel)
                continue
            log(worker_id, f"! 邮箱阶段失败: {msg}")
            _mark_email_stage_error(email, msg)
            traceback.print_exc()
            _inc("reg_fail")
            return None

    try:
        log(worker_id, "4. 填写资料")
        profile = reg.fill_profile_and_submit(
            log_callback=lambda m: log(worker_id, m), cancel_callback=cancel
        )
        log(worker_id, f"资料已填: {profile.get('given_name')} {profile.get('family_name')}")
        log(worker_id, "5. 等待 sso cookie")
        sso = reg.wait_for_sso_cookie(
            log_callback=lambda m: log(worker_id, m), cancel_callback=cancel
        )
        password = profile.get("password", "") or ""
        log(worker_id, "6. 执行 Grok Web 首次激活")
        activation = reg.activate_grok_web_account(
            reg._get_page(),
            log_callback=lambda m: log(worker_id, m),
            cancel_callback=cancel,
        )
        reg.record_web_activation_audit(
            email, activation, log_callback=lambda m: log(worker_id, m)
        )
        if not activation.get("ok"):
            reason = str(activation.get("reason") or "web_activation_failed")
            detail = (
                f"web_activation:{reason}:"
                f"stage={activation.get('stage', 'unknown')}:"
                f"session={activation.get('auth_session_status', 0)}:"
                f"settings={activation.get('user_settings_status', 0)}:"
                f"dom={activation.get('dom_state', 'unknown')}"
            )[:240]
            reg.mark_error(email, password, reason=detail)
            raise reg.ActivationFailedRegistration(email, detail)
        try:
            settle_seconds = max(
                0.0,
                float(
                    (getattr(reg, "config", {}) or {}).get(
                        "registration_post_activation_settle_sec", 5
                    )
                    or 0
                ),
            )
        except Exception:
            settle_seconds = 5.0
        if settle_seconds > 0:
            log(worker_id, f"[activation] 会话完成，等待 {settle_seconds:g}s 后执行 OIDC 健康门")
            reg.sleep_with_cancel(settle_seconds, cancel)
        # Capture cookies BEFORE releasing browser (for mint cookie inject)
        page = reg._get_page()
        cookies = []
        try:
            import cpa_export as _cpa_exp

            cookies = _cpa_exp.export_cookies_from_page(page) if page is not None else []
        except Exception:
            cookies = []
        if cookies:
            log(worker_id, f"[*] 导出 cookie {len(cookies)} 条供 mint 注入")

        # Close by default (or clear only when reuse was explicitly enabled)
        # BEFORE mint so registration and CPA browsers do not overlap needlessly.
        # A rotation lease must never retain Chromium across a node switch, even
        # when this function is invoked directly instead of through CLI main().
        try:
            reg.prepare_browser_for_next_account(
                log_callback=lambda m: log(worker_id, m),
                force_recycle=_rotation_enabled_config(getattr(reg, "config", {}) or {}),
            )
        except Exception:
            try:
                reg.stop_browser()
            except Exception:
                pass

        job = {
            "email": email,
            "password": password,
            "sso": sso,
            "profile": profile,
            "idx": idx,
            "cookies": cookies,
            "activation": activation,
        }

        log(worker_id, f"[*] 注册候选已创建，等待权限健康检查: {email}")
        return job
    except reg.ActivationFailedRegistration:
        raise
    except Exception as exc:
        log(worker_id, f"! 注册失败: {exc}")
        reg.mark_error(email or "", reason=str(exc)[:120])
        traceback.print_exc()
        _inc("reg_fail")
        return None


def _run_mint_job(worker_id: int | str, job: dict[str, Any], config: dict) -> dict:
    """Standalone CPA mint (own Chromium). Never reuses register browser."""
    email = job.get("email") or ""
    password = job.get("password") or ""
    if not email or not password:
        _inc("mint_fail")
        return {"ok": False, "error": "missing email/password", "email": email}
    if not config.get("cpa_export_enabled", True) and not config.get(
        "registration_health_check_enabled", True
    ):
        _inc("mint_skip")
        log(worker_id, f"[cpa] export disabled, skip {email}")
        return {"ok": False, "skipped": True, "email": email}
    try:
        import cpa_export

        mint_cfg = dict(config or {})
        if job.get("egress") and "_egress" not in mint_cfg:
            mint_cfg["_egress"] = job["egress"]

        # page=None always — force standalone path inside export
        result = cpa_export.export_cpa_xai_for_account(
            email,
            password,
            page=None,
            cookies=job.get("cookies"),
            sso=job.get("sso") or "",
            config=mint_cfg,
            log_callback=lambda m: log(worker_id, m),
            cancel=_REGISTER_STOP.is_set,
        )
        if result.get("rejected"):
            log(
                worker_id,
                f"! 健康门拒绝: {email}: "
                f"{result.get('rejection_summary') or result.get('error')}",
            )
        elif result.get("ok") and result.get("path"):
            log(worker_id, f"+ CPA auth: {result.get('path')}")
            _inc("mint_success")
        elif result.get("ok"):
            _inc("mint_skip")
            log(worker_id, f"[cpa] health-only 完成，未写 CPA 文件: {email}")
        elif result.get("skipped"):
            _inc("mint_skip")
            log(worker_id, f"[cpa] skipped: {result.get('reason')}")
        else:
            _inc("mint_fail")
            primary = (
                result.get("auth_code_error")
                or result.get("error")
                or result
            )
            log(
                worker_id,
                f"! CPA auth 未成功: {primary}"
                + (
                    " (device paths skipped under referrer policy)"
                    if result.get("skipped_device")
                    else ""
                ),
            )
        return result
    except Exception as exc:
        _inc("mint_fail")
        log(worker_id, f"! CPA export 异常: {exc}")
        traceback.print_exc()
        return {"ok": False, "error": str(exc), "email": email}


def _success_policy_from_config(cfg: dict | None) -> tuple[bool, bool]:
    """Return (require_cpa_file, require_healthy) for registration commit."""
    cfg = cfg or {}
    # Defaults are strict: 入库 (xai-*.json) + healthy probe = success.
    require_file = bool(cfg.get("registration_success_requires_cpa_file", True))
    require_healthy = bool(cfg.get("registration_success_requires_healthy", True))
    return require_file, require_healthy


def _finalize_candidate(
    worker_id: int | str,
    job: dict[str, Any],
    mint_result: dict[str, Any],
    accounts_file: str,
    *,
    mint_required: bool = False,
    require_cpa_file: bool | None = None,
    require_healthy: bool | None = None,
) -> str:
    """Commit a candidate only when CPA 入库 criteria are met.

    Default product rule (入库才算成功):
      - not health-rejected
      - real CPA auth file path present (xai-*.json written)
      - health.classification == healthy
    """
    email = str(job.get("email") or "")
    password = str(job.get("password") or "")
    sso = str(job.get("sso") or "")
    cfg = getattr(reg, "config", {}) or {}
    if require_cpa_file is None or require_healthy is None:
        pol_file, pol_healthy = _success_policy_from_config(cfg)
        if require_cpa_file is None:
            require_cpa_file = pol_file
        if require_healthy is None:
            require_healthy = pol_healthy
    # Legacy: cpa_mint_required implies file requirement.
    if mint_required:
        require_cpa_file = True

    if mint_result.get("rejected"):
        _inc("health_rejected")
        rejection_summary = str(
            mint_result.get("rejection_summary")
            or mint_result.get("error")
            or "health_gate_rejected"
        )[:240]
        try:
            reg.mark_error(email, password, reason=rejection_summary)
        except Exception:
            pass
        log(worker_id, f"[-] 健康门淘汰候选且不落盘: {email} ({rejection_summary})")
        return "rejected"

    mint_ok = bool(mint_result.get("ok"))
    mint_skipped = bool(mint_result.get("skipped"))
    cpa_path = str(
        mint_result.get("path") or mint_result.get("cpa_path") or ""
    ).strip()
    health = mint_result.get("health") if isinstance(mint_result, dict) else None
    if isinstance(health, dict) and health.get("classification"):
        classification = str(health.get("classification") or "").strip() or "unknown"
        health_present = True
    else:
        # No health block: mint never reached the probe (fail/skip) — not "unknown soft ok".
        classification = "missing"
        health_present = False

    def _reject_commit(reason: str, *, counter: str = "reg_fail") -> str:
        try:
            reg.mark_error(email, password, reason=reason[:240])
        except Exception:
            pass
        _inc(counter)
        log(worker_id, f"[-] 未入库，不记注册成功: {email} ({reason})")
        return "failed"

    # Explicit mint_required soft-fail (also covered by path gate when require_cpa_file).
    if (
        mint_required
        and not mint_ok
        and not mint_skipped
        and not mint_result.get("rejected")
    ):
        reason = str(
            mint_result.get("auth_code_error")
            or mint_result.get("error")
            or "cpa_mint_required"
        )[:240]
        return _reject_commit(f"cpa_mint_required:{reason}")

    if require_cpa_file and not mint_skipped and not cpa_path:
        detail = str(
            mint_result.get("auth_code_error")
            or mint_result.get("error")
            or ("mint_ok_without_path" if mint_ok else "mint_failed")
        )[:200]
        return _reject_commit(f"no_cpa_file:{detail}")

    if require_healthy and not mint_skipped:
        if not health_present or classification != "healthy":
            detail = classification if health_present else "health_missing"
            if not mint_ok:
                detail = (
                    f"{detail}:"
                    f"{mint_result.get('auth_code_error') or mint_result.get('error') or 'mint_failed'}"
                )[:200]
            return _reject_commit(
                f"health_not_healthy:{detail}", counter="health_unknown"
            )

    # Soft / legacy mode only: keep non-healthy when policy allows.
    if classification != "healthy" and not mint_skipped:
        _inc("health_unknown")
        log(
            worker_id,
            f"[health] 非 healthy，按宽松策略保留: {email} ({classification})",
        )

    if not mint_ok and not mint_skipped and not require_cpa_file:
        log(
            worker_id,
            f"[*] 宽松策略：CPA 未写出仍落盘 SSO: {email}: "
            f"{mint_result.get('auth_code_error') or mint_result.get('error') or 'mint_failed'}",
        )

    line = f"{email}----{password}----{sso}\n"
    with _accounts_lock:
        with open(accounts_file, "a", encoding="utf-8") as f:
            f.write(line)
    try:
        reg.mark_used(email, password)
    except Exception:
        pass
    if job.get("cookies") and reg.PERF_FLAGS.get("cookie_snapshot", True):
        try:
            reg.save_exported_cookies_snapshot(job["cookies"], "success", email)
        except Exception:
            pass
    try:
        reg.add_token_to_grok2api_pools(
            sso, email=email, log_callback=lambda m: log(worker_id, m)
        )
    except Exception as exc:
        log(worker_id, f"[Debug] grok2api: {exc}")
    _inc("reg_success")
    if cpa_path:
        log(worker_id, f"[+] 入库成功 path={cpa_path}")
    if classification == "healthy":
        log(worker_id, f"[+] 注册成功并通过健康门: {email}")
    else:
        log(worker_id, f"[+] 注册成功（宽松策略）: {email} ({classification})")
    return "accepted"


def _emit_outcome(outcome_queue: queue.Queue | None, job: dict[str, Any], status: str) -> None:
    if outcome_queue is None:
        return
    outcome_queue.put(
        {
            "slot": job.get("slot"),
            "replacement": int(job.get("replacement", 0) or 0),
            "status": status,
            "idx": job.get("idx"),
        }
    )


def _safe_finalize_candidate(
    worker_id: int | str,
    job: dict[str, Any],
    mint_result: dict[str, Any],
    accounts_file: str,
    *,
    mint_required: bool = False,
    require_cpa_file: bool | None = None,
    require_healthy: bool | None = None,
) -> str:
    try:
        return _finalize_candidate(
            worker_id,
            job,
            mint_result,
            accounts_file,
            mint_required=mint_required,
            require_cpa_file=require_cpa_file,
            require_healthy=require_healthy,
        )
    except Exception as exc:
        _inc("reg_fail")
        log(worker_id, f"! 候选提交失败: {exc}")
        try:
            reg.mark_error(str(job.get("email") or ""), reason=str(exc)[:120])
        except Exception:
            pass
        return "failed"


def _register_worker(
    worker_id: int,
    task_queue: queue.Queue,
    total: int,
    accounts_file: str,
    mint_queue: queue.Queue | None,
    forever: bool,
    do_mint_inline: bool,
    outcome_queue: queue.Queue | None = None,
):
    while not _REGISTER_STOP.is_set() and not _REGISTER_CAPACITY_STOP.is_set():
        try:
            task = task_queue.get(timeout=0.5)
        except queue.Empty:
            if not forever:
                if _SCHEDULER_DONE.is_set():
                    break
                continue
            if _REGISTER_STOP.is_set():
                break
            with _next_idx_lock:
                nxt = _next_idx[0]
                _next_idx[0] = nxt + 5
            for i in range(nxt, nxt + 5):
                task_queue.put({"idx": i, "slot": None, "replacement": 0})
            continue

        if task is _TASK_STOP:
            task_queue.task_done()
            break
        if isinstance(task, int):
            task = {"idx": task, "slot": task, "replacement": 0}
        elif not isinstance(task, dict):
            task_queue.task_done()
            continue
        idx = int(task.get("idx") or 0)

        retry = 0
        candidate = None
        activation_failure = None
        terminal_status = "failed"
        outcome_deferred = False
        mint_result_for_rot: dict | None = None
        emit_job: dict = task
        rot_mgr = None
        lease = None
        try:
            cfg = getattr(reg, "config", {}) or {}
            if _rotation_enabled_config(cfg):
                try:
                    import proxy_rotation as proxy_rot

                    rot_mgr = proxy_rot.get_manager(
                        cfg,
                        log=lambda m: log(worker_id, m),
                    )
                except Exception as exc:
                    log(worker_id, f"[proxy-rot] manager unavailable; stop batch: {exc}")
                    _REGISTER_STOP.set()

            while retry < 2 and not _REGISTER_STOP.is_set() and not _REGISTER_CAPACITY_STOP.is_set():
                result = None
                if rot_mgr is not None:
                    try:
                        lease = rot_mgr.acquire(cancel=_REGISTER_STOP.is_set)
                    except Exception as exc:
                        log(worker_id, f"[proxy-rot] 无法获取合格出口，批次停止: {exc}")
                        _REGISTER_STOP.set()
                        terminal_status = "failed"
                        break
                try:
                    result = register_one(
                        worker_id,
                        idx,
                        total,
                    )
                    if result:
                        candidate = result
                        break
                    if _REGISTER_CAPACITY_STOP.is_set():
                        break
                    _release_rotation_lease(worker_id, rot_mgr, lease, "failed")
                    lease = None
                    retry += 1
                    if retry < 2 and not _REGISTER_STOP.is_set():
                        log(
                            worker_id,
                            f"[retry] 账号 {idx} 失败，释放当前出口并重新获取 lease，重试 {retry}/1",
                        )
                except reg.ActivationFailedRegistration as exc:
                    activation_failure = exc
                    _inc("activation_failed")
                    log(worker_id, f"[-] Web 激活失败，候选淘汰: {exc.reason}")
                    break
                except Exception:
                    _release_rotation_lease(worker_id, rot_mgr, lease, "failed")
                    lease = None
                    retry += 1
                    if retry < 2 and not _REGISTER_STOP.is_set():
                        log(
                            worker_id,
                            f"[retry] 账号 {idx} 异常，释放当前出口并重新获取 lease，重试 {retry}/1",
                        )
                        traceback.print_exc()
                finally:
                    # Failed sessions are always dirty. Successful sessions are
                    # also closed unless --browser-reuse was explicitly enabled.
                    if (
                        not result
                        or rot_mgr is not None
                        or not reg.PERF_FLAGS.get("browser_reuse", False)
                    ):
                        try:
                            reg.stop_browser()
                        except Exception:
                            pass

            if candidate:
                candidate.update(task)
                emit_job = candidate
                if lease is not None and rot_mgr is not None:
                    candidate["egress"] = rot_mgr.describe(lease)
                if do_mint_inline or rot_mgr is not None:
                    mint_cfg = dict(getattr(reg, "config", {}) or {})
                    if rot_mgr is not None:
                        mint_cfg["cpa_mint_browser_reuse"] = False
                    if candidate.get("egress"):
                        mint_cfg["_egress"] = candidate["egress"]
                    mint_result = _run_mint_job(f"R{worker_id}", candidate, mint_cfg)
                    mint_result_for_rot = mint_result if isinstance(mint_result, dict) else None
                    if _REGISTER_STOP.is_set():
                        terminal_status = "failed"
                    else:
                        terminal_status = _safe_finalize_candidate(
                            f"R{worker_id}",
                            candidate,
                            mint_result,
                            accounts_file,
                            mint_required=bool(
                                mint_cfg.get("cpa_mint_required", False)
                            ),
                        )
                elif mint_queue is not None:
                    qmax = int(getattr(mint_queue, "_reg_qmax", 0) or 0)
                    while qmax > 0 and mint_queue.qsize() >= qmax and not _REGISTER_STOP.is_set():
                        log(worker_id, f"[cpa] mint 队列背压 qsize={mint_queue.qsize()}≥{qmax}，等待...")
                        time.sleep(1.0)
                    candidate["accounts_file"] = accounts_file
                    candidate["outcome_queue"] = outcome_queue
                    # Without serial rotation, mint worker may run after another
                    # account switched nodes — keep egress metadata for audit only.
                    mint_queue.put(candidate)
                    log(
                        worker_id,
                        f"[cpa] enqueued health+mint for {candidate.get('email')} "
                        f"(queue≈{mint_queue.qsize()})",
                    )
                    # The mint worker owns the only terminal outcome for this
                    # attempt. Emitting here would let the scheduler complete the
                    # slot before the health gate can reject and request a refill.
                    outcome_deferred = True
                else:
                    terminal_status = _safe_finalize_candidate(
                        worker_id, candidate, {"ok": False, "skipped": True}, accounts_file
                    )
            elif activation_failure is not None:
                terminal_status = "activation_failed"
            else:
                terminal_status = "failed"
        finally:
            _release_rotation_lease(
                worker_id,
                rot_mgr,
                lease,
                terminal_status,
                mint_result_for_rot,
            )
        if not outcome_deferred:
            _emit_outcome(outcome_queue, emit_job, terminal_status)
        task_queue.task_done()

    # worker exit: free browser
    try:
        reg.stop_browser()
    except Exception:
        pass
    log(worker_id, "register worker exit")


def _mint_worker(worker_id: str, mint_queue: queue.Queue, config: dict):
    while True:
        job = mint_queue.get()
        try:
            if job is _MINT_STOP:
                break
            if not isinstance(job, dict):
                continue
            result = _run_mint_job(worker_id, job, config)
            if _REGISTER_STOP.is_set():
                status = "failed"
            else:
                status = _safe_finalize_candidate(
                    worker_id,
                    job,
                    result,
                    str(job.get("accounts_file") or "accounts_cli.txt"),
                    mint_required=bool(
                        (config or {}).get("cpa_mint_required", False)
                    ),
                )
            _emit_outcome(job.get("outcome_queue"), job, status)
        finally:
            mint_queue.task_done()
    try:
        from cpa_xai.browser_confirm import shutdown_mint_browsers

        shutdown_mint_browsers()
    except Exception:
        pass
    log(worker_id, "mint worker exit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CLI runner for grok_register_ttk (pipelined).")
    parser.add_argument("--count", type=int, default=1, help="账号总数目标（0=不限；含已有）")
    parser.add_argument(
        "--extra",
        type=int,
        default=0,
        help="在已有 accounts 基础上再新注册 N 个",
    )
    parser.add_argument("--threads", type=int, default=1, help="注册并发线程数（1-10）")
    parser.add_argument(
        "--mint-workers",
        type=int,
        default=-1,
        help="CPA mint 并发：-1=用 config/auto；0=内联；1-10=固定。覆盖 config.cpa_mint_workers",
    )
    parser.add_argument(
        "--mint-queue-max",
        type=int,
        default=-1,
        help="mint 队列背压上限：-1=用 config/auto(2×workers)；0=不限制",
    )
    parser.add_argument("--accounts-file", default=os.path.join(os.path.dirname(__file__), "accounts_cli.txt"))
    parser.add_argument("--fast", action="store_true", default=True, help="快速模式（默认开）：压缩 sleep、关截图")
    parser.add_argument("--no-fast", action="store_true", help="关闭快速模式")
    browser_group = parser.add_mutually_exclusive_group()
    browser_group.add_argument(
        "--browser-reuse",
        action="store_true",
        help="显式复用每个注册 worker 的浏览器（默认每账号关闭）",
    )
    browser_group.add_argument(
        "--no-browser-reuse",
        action="store_true",
        help="兼容旧参数：每账号关闭浏览器（已是默认）",
    )
    parser.add_argument("--browser-recycle-every", type=int, default=25, help="复用 N 次后完整回收")
    parser.add_argument("--cookie-snapshot", action="store_true", help="注册成功写 cookie 快照（默认关，fast）")
    parser.add_argument("--inline-mint", action="store_true", help="强制注册线程内联 mint（调试用）")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    _REGISTER_STOP.clear()
    _REGISTER_CAPACITY_STOP.clear()
    _SCHEDULER_DONE.clear()
    with _stats_lock:
        for key in list(_stats):
            _stats[key] = 0

    reg.load_config()
    cfg0 = getattr(reg, "config", {}) or {}
    try:
        rotation_manager = _prepare_rotation_manager(
            cfg0,
            log_callback=lambda message: print(message, flush=True),
        )
    except Exception as exc:
        print(f"[proxy-rot] 配置/出口校验失败，任务未启动: {exc}", flush=True)
        return 1
    rotation_active = rotation_manager is not None
    if rotation_active:
        # One mixed-port lease must cover register + mint + health as one serial unit.
        cfg0["cpa_mint_browser_reuse"] = False
    threads = max(1, min(args.threads, 10))
    fast = bool(args.fast) and not bool(args.no_fast)

    mint_workers = resolve_mint_workers(
        cli_value=args.mint_workers,
        threads=threads,
        config=cfg0,
        inline_mint=bool(args.inline_mint),
    )
    try:
        import proxy_rotation as _proxy_rot

        threads, mint_workers, rot_forced = _proxy_rot.apply_rotation_concurrency(
            cfg0, threads, mint_workers
        )
        if rot_forced:
            print(
                f"[proxy-rot] rotation enabled → force register_threads=1 mint_workers=0 "
                f"(was threads={args.threads} mint_workers={args.mint_workers})",
                flush=True,
            )
    except Exception as exc:
        if rotation_active:
            print(f"[proxy-rot] 并发约束失败，任务未启动: {exc}", flush=True)
            return 1
        print(f"[proxy-rot] concurrency clamp skipped: {exc}", flush=True)
    do_mint_inline = mint_workers == 0
    mint_qmax = resolve_mint_queue_max(
        cfg0,
        mint_workers,
        cli_value=(None if args.mint_queue_max < 0 else args.mint_queue_max),
    )

    # perf knobs
    requested_browser_reuse = bool(args.browser_reuse) and not bool(args.no_browser_reuse)
    if rotation_active and requested_browser_reuse:
        print(
            "[proxy-rot] rotation enabled → disable registration browser reuse",
            flush=True,
        )
    reg.configure_perf(
        fast=fast,
        sleep_scale=0.15 if fast else 1.0,
        skip_debug_io=fast,
        cookie_snapshot=bool(args.cookie_snapshot) or not fast,
        async_side_effects=True,
        browser_reuse=requested_browser_reuse and not rotation_active,
        browser_recycle_every=max(1, int(args.browser_recycle_every)),
    )

    # 断点续跑
    done_count = 0
    if os.path.exists(args.accounts_file):
        with open(args.accounts_file) as f:
            done_count = sum(1 for line in f if line.strip())

    if args.extra and args.extra > 0:
        target_total = done_count + args.extra
        remaining = args.extra
        print(
            f"[*] 配置加载完成，额外新注册 {args.extra} 个（当前已有 {done_count} → 目标 {target_total}），"
            f"注册线程={threads} mint_workers={mint_workers} mint_queue_max={mint_qmax} fast={fast}",
            flush=True,
        )
        args.count = target_total
    elif args.count == 0:
        remaining = None
        print(
            f"[*] 配置加载完成，不限数量，注册线程={threads} mint_workers={mint_workers} mint_queue_max={mint_qmax} fast={fast}",
            flush=True,
        )
    else:
        remaining = max(0, args.count - done_count)
        print(
            f"[*] 配置加载完成，目标 {args.count} 个账号，注册线程={threads} "
            f"mint_workers={mint_workers} mint_queue_max={mint_qmax} fast={fast}",
            flush=True,
        )
    print(f"[*] accounts_file = {args.accounts_file}", flush=True)
    if done_count > 0:
        print(f"[*] 断点续跑：已完成 {done_count}", flush=True)
    if remaining is not None and remaining <= 0:
        print("[*] 所有账号已完成，无需继续（可用 --extra N 再注册）", flush=True)
        return 0

    if str(cfg0.get("email_provider") or "").strip().lower() in {"custommail", "custom_mail"}:
        try:
            capacity = reg.get_custom_mail_capacity()
        except Exception as exc:
            print(f"[!] CustomMail 容量检查失败: {exc}", flush=True)
            return 1
        available = int(capacity["remaining"])
        print(
            f"[*] CustomMail 容量: 剩余 {available}/{capacity['total']}，"
            f"域名数 {capacity['accounts']}",
            flush=True,
        )
        if available <= 0:
            print("[!] CustomMail 地址已耗尽，任务未启动", flush=True)
            return 1
        if remaining is None or remaining > available:
            requested = "不限" if remaining is None else str(remaining)
            remaining = available
            args.count = done_count + available
            print(
                f"[!] 待注册数量 {requested} 超过剩余容量，自动缩减为 {available}",
                flush=True,
            )

    log_thread = threading.Thread(target=_log_writer, daemon=True)
    log_thread.start()

    try:
        reg.TabPool.allow_new()
        reg.TabPool.init(reg.create_browser_options, log_callback=lambda m: log(0, m))
    except Exception as exc:
        print(f"[!] 浏览器初始化失败: {exc}", flush=True)
        return 1

    task_queue: queue.Queue = queue.Queue()
    outcome_queue: queue.Queue | None = queue.Queue() if remaining is not None else None
    mint_queue: queue.Queue | None = queue.Queue() if not do_mint_inline else None
    if mint_queue is not None:
        mint_queue._reg_qmax = mint_qmax  # type: ignore[attr-defined]
    global _next_idx
    if remaining is not None:
        for slot, i in enumerate(range(done_count + 1, args.count + 1), 1):
            task_queue.put({"idx": i, "slot": slot, "replacement": 0})
        _next_idx[0] = args.count + 1
    else:
        for i in range(done_count + 1, done_count + threads * 5 + 1):
            task_queue.put({"idx": i, "slot": None, "replacement": 0})
        _next_idx[0] = done_count + threads * 5 + 1

    forever = remaining is None
    cfg = getattr(reg, "config", {}) or {}

    # mint workers first (so queue consumers ready)
    mint_threads: list[threading.Thread] = []
    if mint_queue is not None and mint_workers > 0:
        for i in range(1, mint_workers + 1):
            wid = f"M{i}"
            t = threading.Thread(
                target=_mint_worker,
                args=(wid, mint_queue, cfg),
                daemon=True,
                name=f"mint-{i}",
            )
            t.start()
            mint_threads.append(t)

    reg_threads: list[threading.Thread] = []
    for wid in range(1, threads + 1):
        t = threading.Thread(
            target=_register_worker,
            args=(
                wid,
                task_queue,
                args.count,
                args.accounts_file,
                mint_queue,
                forever,
                do_mint_inline,
                outcome_queue,
            ),
            daemon=True,
            name=f"reg-{wid}",
        )
        t.start()
        reg_threads.append(t)

    try:
        if remaining is not None and outcome_queue is not None:
            completed_slots = 0
            raw_limit = cfg.get("registration_health_max_replacements_per_slot", 3)
            max_replacements = max(0, int(3 if raw_limit is None else raw_limit))
            while completed_slots < remaining and not _REGISTER_STOP.is_set():
                if _REGISTER_CAPACITY_STOP.is_set():
                    log(0, "[health] 邮箱容量耗尽，停止补号并保留已完成结果")
                    break
                try:
                    outcome = outcome_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                status = str(outcome.get("status") or "failed")
                replacement = int(outcome.get("replacement", 0) or 0)
                slot = outcome.get("slot")
                if status in {"rejected", "activation_failed"} and replacement < max_replacements:
                    with _next_idx_lock:
                        idx = _next_idx[0]
                        _next_idx[0] += 1
                    task_queue.put(
                        {"idx": idx, "slot": slot, "replacement": replacement + 1}
                    )
                    log(
                        0,
                        f"[health] 槽位 {slot} 候选淘汰({status})，补注册 "
                        f"{replacement + 1}/{max_replacements}",
                    )
                else:
                    if status in {"rejected", "activation_failed"}:
                        _inc("reg_fail")
                        log(0, f"[health] 槽位 {slot} 已达到最大补号次数")
                    completed_slots += 1
            _SCHEDULER_DONE.set()
            while True:
                try:
                    task_queue.get_nowait()
                    task_queue.task_done()
                except queue.Empty:
                    break
            for _ in reg_threads:
                task_queue.put(_TASK_STOP)
        for t in reg_threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] 用户中断", flush=True)
        _REGISTER_STOP.set()
        _SCHEDULER_DONE.set()
        try:
            reg.shutdown_browser(block_new=True)
        except Exception:
            pass
        for t in reg_threads:
            t.join(timeout=30)

    # drain mint queue
    if mint_queue is not None:
        log(0, f"[cpa] 等待 mint 队列清空（qsize≈{mint_queue.qsize()}）...")
        mint_queue.join()
        for _ in mint_threads:
            mint_queue.put(_MINT_STOP)
        for t in mint_threads:
            t.join(timeout=600)

    try:
        reg.shutdown_browser(block_new=True)
    except Exception:
        pass

    # stop side-effect pool
    try:
        pool = getattr(reg, "_side_effect_pool", None)
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass

    _log_queue.put(None)
    log_thread.join(timeout=2)

    with _stats_lock:
        s = dict(_stats)
    print(
        f"=== 完成: 注册成功 {s.get('reg_success', 0)}, 注册失败 {s.get('reg_fail', 0)}, "
        f"CPA成功 {s.get('mint_success', 0)}, CPA失败 {s.get('mint_fail', 0)}, "
        f"CPA跳过 {s.get('mint_skip', 0)}, 权限拒绝 {s.get('health_rejected', 0)}, "
        f"Web激活失败 {s.get('activation_failed', 0)}, "
        f"探测非健康但保留 {s.get('health_unknown', 0)} ===",
        flush=True,
    )
    return 0 if s.get("reg_success", 0) > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
