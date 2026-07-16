#!/usr/bin/env python3
"""Web-activate ledger accounts (birthday + first message), then health-gated CPA mint.

For old accounts_*.txt rows that can mint OIDC but fail chat with permission_denied.
Mirrors GUI health-recovery: password login → grok.com activate → OIDC health gate.

Example:
  uv run python -u scripts/activate_web_and_mint_from_accounts.py \\
    --accounts accounts_20260713_231340.txt \\
    --limit 1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cpa_xai import existing_cpa_emails, parse_accounts_file  # noqa: E402


def _load_config(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"warn: read config failed: {exc}", flush=True)
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        k: v
        for k, v in raw.items()
        if not (isinstance(k, str) and (k.startswith("//") or k.startswith("#")))
    }


def _cpa_path(auth_dir: Path, email: str) -> Path:
    return auth_dir / f"xai-{email}.json"


def _delete_cpa(auth_dir: Path, email: str, log) -> None:
    path = _cpa_path(auth_dir, email)
    if not path.is_file():
        return
    try:
        path.unlink()
        log(f"removed CPA file: {path}")
    except OSError as exc:
        log(f"failed to remove CPA {path}: {exc}")


def _activate_one(
    *,
    email: str,
    password: str,
    sso: str,
    reg,
    prefer_sso_inject: bool,
    log,
    cancel,
) -> dict:
    """Login (SSO inject or password) → activate_grok_web_account.

    Returns dict with ok, sso, cookies, activation, reason?
    """
    result: dict = {
        "ok": False,
        "email": email,
        "sso": "",
        "cookies": [],
        "activation": None,
        "login_method": None,
    }

    try:
        reg.stop_browser()
    except Exception:
        pass
    reg.start_browser(log_callback=log)

    page = reg._get_page()
    if page is None:
        result["reason"] = "browser_page_unavailable"
        return result

    active_sso = (sso or "").strip()
    used_sso_inject = False

    if prefer_sso_inject and active_sso:
        log("try SSO cookie inject → grok.com")
        try:
            import cpa_export
            from cpa_xai.browser_confirm import inject_cookies

            cookie_list = []
            for name in ("sso", "sso-rw"):
                for dom in (
                    ".x.ai",
                    "accounts.x.ai",
                    ".accounts.x.ai",
                    "auth.x.ai",
                    "grok.com",
                    ".grok.com",
                ):
                    cookie_list.append(
                        {
                            "name": name,
                            "value": active_sso,
                            "domain": dom,
                            "path": "/",
                            "secure": True,
                            "httpOnly": True,
                        }
                    )
            inject_cookies(page, cookie_list, log=log)
            try:
                page.get("https://grok.com/", timeout=60)
            except TypeError:
                page.get("https://grok.com/")
            auth = reg.wait_for_authenticated_grok_page(
                page,
                log_callback=log,
                cancel_callback=cancel,
                timeout=45,
            )
            if auth.get("ok"):
                used_sso_inject = True
                result["login_method"] = "sso_inject"
                log("SSO inject authenticated on grok.com")
            else:
                log(f"SSO inject auth failed: {auth.get('reason')}; fallback password login")
        except Exception as exc:  # noqa: BLE001
            log(f"SSO inject exception: {exc}; fallback password login")

    if not used_sso_inject:
        log("password login for web activation")
        try:
            # Clean slate for login form
            try:
                reg.prepare_browser_for_next_account(log_callback=log, force_recycle=False)
            except Exception:
                pass
            if reg._get_page() is None:
                reg.start_browser(log_callback=log)
            active_sso = reg.login_and_get_sso(
                email,
                password,
                log_callback=log,
                cancel_callback=cancel,
            )
            result["login_method"] = "password"
            page = reg._get_page()
            if page is None:
                result["reason"] = "page_lost_after_login"
                return result
            auth = reg.wait_for_authenticated_grok_page(
                page,
                log_callback=log,
                cancel_callback=cancel,
                timeout=60,
            )
            if not auth.get("ok"):
                result["reason"] = f"grok_auth_failed:{auth.get('reason')}"
                return result
            try:
                page.get("https://grok.com/", timeout=60)
            except TypeError:
                page.get("https://grok.com/")
        except Exception as exc:  # noqa: BLE001
            result["reason"] = f"login_failed:{exc}"
            return result

    page = reg._get_page()
    log("running activate_grok_web_account (birthday + first message)")
    activation = reg.activate_grok_web_account(
        page,
        log_callback=log,
        cancel_callback=cancel,
        timeout=120,
    )
    result["activation"] = activation
    if not activation.get("ok"):
        result["reason"] = f"activation_failed:{activation.get('reason')}"
        return result

    cookies = []
    try:
        import cpa_export

        cookies = cpa_export.export_cookies_from_page(page) or []
    except Exception as exc:  # noqa: BLE001
        log(f"cookie export failed: {exc}")

    # Prefer fresh sso from browser if present
    if cookies:
        for c in cookies:
            if isinstance(c, dict) and c.get("name") in ("sso", "sso-rw") and c.get("value"):
                active_sso = str(c.get("value"))
                break

    result["ok"] = True
    result["sso"] = active_sso or ""
    result["cookies"] = cookies
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--accounts", default=str(_ROOT / "accounts_cli.txt"))
    ap.add_argument("--config", default=str(_ROOT / "config.json"))
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--email", default="", help="Only this email")
    ap.add_argument("--skip-existing", action="store_true", default=True)
    ap.add_argument("--no-skip-existing", action="store_false", dest="skip_existing")
    ap.add_argument(
        "--skip-healthy-cpa",
        action="store_true",
        default=True,
        help="Skip emails that already have cpa_auths/xai-*.json (default)",
    )
    ap.add_argument("--no-skip-healthy-cpa", action="store_false", dest="skip_healthy_cpa")
    ap.add_argument(
        "--prefer-sso-inject",
        action="store_true",
        default=True,
        help="Try ledger SSO cookie inject before password login (default)",
    )
    ap.add_argument("--no-prefer-sso-inject", action="store_false", dest="prefer_sso_inject")
    ap.add_argument(
        "--mint",
        action="store_true",
        default=True,
        help="After activation, run health-gated CPA mint (default)",
    )
    ap.add_argument("--no-mint", action="store_false", dest="mint")
    ap.add_argument(
        "--require-healthy",
        action="store_true",
        default=True,
        help="Strict: only keep CPA when classification==healthy (default)",
    )
    ap.add_argument("--no-require-healthy", action="store_false", dest="require_healthy")
    ap.add_argument("--sleep", type=float, default=5.0)
    ap.add_argument(
        "--fail-log",
        default=str(_ROOT / "cpa_auths" / "activate_mint_failed.jsonl"),
    )
    ap.add_argument(
        "--success-log",
        default=str(_ROOT / "cpa_auths" / "activate_mint_success.jsonl"),
    )
    args = ap.parse_args()

    cfg = _load_config(Path(args.config))
    # Ensure health gate is on for mint path
    cfg.setdefault("registration_health_check_enabled", True)
    cfg.setdefault("cpa_export_enabled", True)

    out_raw = (cfg.get("cpa_auth_dir") or str(_ROOT / "cpa_auths")).strip()
    out_dir = Path(out_raw).expanduser()
    if not out_dir.is_absolute():
        out_dir = (_ROOT / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    accounts = parse_accounts_file(args.accounts)
    if args.email:
        accounts = [a for a in accounts if a.email.lower() == args.email.lower()]
    accounts = accounts[args.offset :]

    have = set()
    if args.skip_healthy_cpa:
        have = {e.lower() for e in existing_cpa_emails(out_dir)}

    todo = []
    for a in accounts:
        if args.skip_healthy_cpa and a.email.lower() in have:
            continue
        todo.append(a)
        if args.limit and len(todo) >= args.limit:
            break

    print(
        f"accounts total={len(parse_accounts_file(args.accounts))} "
        f"todo={len(todo)} mint={args.mint} require_healthy={args.require_healthy} "
        f"prefer_sso_inject={args.prefer_sso_inject}",
        flush=True,
    )
    if not todo:
        print("nothing to do", flush=True)
        return 0

    import grok_register_ttk as reg

    # Align module config with file for export_cpa_after_success
    try:
        reg.config.update(cfg)
    except Exception:
        pass

    ok_n = act_fail_n = mint_fail_n = rejected_n = 0
    results: list[dict] = []

    def cancel() -> bool:
        return False

    for i, acc in enumerate(todo, 1):
        print(f"\n=== [{i}/{len(todo)}] {acc.email} ===", flush=True)

        def log(msg: str, _email=acc.email) -> None:
            print(f"[{time.strftime('%H:%M:%S')}] [{_email}] {msg}", flush=True)

        row: dict = {"email": acc.email, "ok": False}
        try:
            act = _activate_one(
                email=acc.email,
                password=acc.password,
                sso=acc.sso or "",
                reg=reg,
                prefer_sso_inject=args.prefer_sso_inject,
                log=log,
                cancel=cancel,
            )
            row["activation"] = {
                "ok": act.get("ok"),
                "login_method": act.get("login_method"),
                "reason": act.get("reason"),
                "detail": act.get("activation"),
            }
            if not act.get("ok"):
                act_fail_n += 1
                row["error"] = act.get("reason") or "activation_failed"
                log(f"ACTIVATION FAIL: {row['error']}")
                if args.fail_log:
                    Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                    with open(args.fail_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                results.append(row)
                continue

            log(
                f"activation OK method={act.get('login_method')} "
                f"birth_saved={((act.get('activation') or {}).get('birth_date_saved'))}"
            )

            if not args.mint:
                ok_n += 1
                row["ok"] = True
                row["mint_skipped"] = True
                results.append(row)
                continue

            # Match GUI health-recovery: keep the warm browser session for OIDC,
            # then fall back to standalone protocol if needed.
            sso_val = act.get("sso") or acc.sso or ""
            cookies = act.get("cookies") or []
            settle = float(cfg.get("registration_post_activation_settle_sec", 5) or 5)
            if settle > 0:
                log(f"post-activation settle {settle:g}s before OIDC health mint")
                time.sleep(settle)

            import cpa_export

            page = reg._get_page()
            mint_cfg = dict(cfg)
            mint_cfg["registration_health_check_enabled"] = True
            # Same-session browser OIDC first (recovery path).
            mint_cfg["cpa_prefer_protocol"] = False
            mint_cfg["cpa_force_standalone"] = False
            mint_cfg["cpa_mint_cookie_inject"] = False
            mint_cfg["cpa_mint_browser_reuse"] = False

            mint_result = cpa_export.export_cpa_xai_for_account(
                email=acc.email,
                password=acc.password,
                page=page,
                sso=sso_val,
                cookies=cookies,
                config=mint_cfg,
                log_callback=log,
            )
            # If browser mint failed non-health, retry protocol standalone.
            if (
                not mint_result.get("ok")
                and not mint_result.get("rejected")
                and not (
                    isinstance(mint_result.get("health"), dict)
                    and mint_result["health"].get("classification")
                )
            ):
                log(f"browser mint failed ({mint_result.get('error')}); retry protocol standalone")
                try:
                    reg.prepare_browser_for_next_account(log_callback=log)
                except Exception:
                    try:
                        reg.stop_browser()
                    except Exception:
                        pass
                mint_cfg2 = dict(cfg)
                mint_cfg2["registration_health_check_enabled"] = True
                mint_cfg2["cpa_prefer_protocol"] = True
                mint_cfg2["cpa_force_standalone"] = True
                mint_result = cpa_export.export_cpa_xai_for_account(
                    email=acc.email,
                    password=acc.password,
                    sso=sso_val,
                    cookies=cookies,
                    config=mint_cfg2,
                    log_callback=log,
                )
            row["mint"] = {
                "ok": mint_result.get("ok"),
                "rejected": mint_result.get("rejected"),
                "path": mint_result.get("path"),
                "error": mint_result.get("error") or mint_result.get("rejection_summary"),
                "health": mint_result.get("health"),
                "mint_method": mint_result.get("mint_method"),
            }
            health = mint_result.get("health") if isinstance(mint_result.get("health"), dict) else {}
            classification = str(health.get("classification") or "")

            strict_unhealthy = bool(
                args.require_healthy
                and classification
                and classification != "healthy"
            )
            if mint_result.get("rejected") or strict_unhealthy:
                rejected_n += 1
                _delete_cpa(out_dir, acc.email, log)
                # Also drop path written before strict classification check
                for path_key in ("path", "cpa_path"):
                    raw = mint_result.get(path_key)
                    if raw:
                        try:
                            Path(raw).unlink(missing_ok=True)
                        except OSError:
                            pass
                row["error"] = (
                    mint_result.get("rejection_summary")
                    or mint_result.get("error")
                    or f"unhealthy:{classification or 'unknown'}"
                )
                log(f"MINT REJECTED health={classification or 'n/a'} {row['error']}")
                if args.fail_log:
                    Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                    with open(args.fail_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            elif mint_result.get("ok") and mint_result.get("path"):
                ok_n += 1
                row["ok"] = True
                log(f"OK CPA={mint_result.get('path')} health={classification or 'n/a'}")
                if args.success_log:
                    Path(args.success_log).parent.mkdir(parents=True, exist_ok=True)
                    with open(args.success_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            else:
                mint_fail_n += 1
                row["error"] = mint_result.get("error") or "mint_failed"
                log(f"MINT FAIL: {row['error']}")
                if args.fail_log:
                    Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                    with open(args.fail_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        except Exception as exc:  # noqa: BLE001
            act_fail_n += 1
            row["error"] = f"exception:{exc}"
            log(f"EXCEPTION: {exc}")
            if args.fail_log:
                Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                with open(args.fail_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        finally:
            results.append(row)
            try:
                reg.stop_browser()
            except Exception:
                pass
            if args.sleep and i < len(todo):
                time.sleep(args.sleep)

    print(
        f"\n=== done ok={ok_n} activation_fail={act_fail_n} "
        f"mint_rejected={rejected_n} mint_fail={mint_fail_n} ===",
        flush=True,
    )
    summary = out_dir / f"activate_mint_summary_{int(time.time())}.json"
    summary.write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"summary {summary}", flush=True)
    return 0 if ok_n > 0 or not todo else 1


if __name__ == "__main__":
    raise SystemExit(main())
