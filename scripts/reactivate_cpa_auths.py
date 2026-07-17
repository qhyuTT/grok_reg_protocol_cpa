#!/usr/bin/env python3
"""Safely re-activate existing CPA accounts and commit only healthy results.

This wrapper intentionally keeps the live ``cpa_auths`` directory untouched
until an account completes web activation, OAuth minting, and the health gate.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cpa_xai import parse_accounts_file  # noqa: E402
from scripts.activate_web_and_mint_from_accounts import (  # noqa: E402
    _activate_one,
    _load_config,
)


def _default_account_files() -> list[Path]:
    return sorted(_ROOT.glob("accounts_*.txt"))


def _load_accounts(paths: list[Path]):
    by_email = {}
    duplicates = []
    for path in paths:
        for account in parse_accounts_file(path):
            key = account.email.strip().lower()
            if key in by_email:
                duplicates.append(key)
                continue
            by_email[key] = account
    return list(by_email.values()), sorted(set(duplicates))


def _safe_label(email: str) -> str:
    local, sep, domain = email.partition("@")
    if not sep:
        return "***"
    return f"{local[:2]}***@{domain}"


def _atomic_install(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.reactivate.tmp")
    shutil.copy2(source, temporary)
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)


def run(*, account_files: list[Path], config_path: Path, live_dir: Path, sleep_sec: float,
        max_accounts: int = 0, stop_after_egress_403: int = 2) -> dict:
    accounts, duplicates = _load_accounts(account_files)
    live_files = {p.stem.removeprefix("xai-").lower(): p for p in live_dir.glob("xai-*.json")}
    targets = [a for a in accounts if a.email.lower() in live_files]
    if max_accounts:
        targets = targets[:max_accounts]

    cfg = _load_config(config_path)
    cfg["registration_health_check_enabled"] = True
    cfg["cpa_export_enabled"] = True
    cfg["cpa_prefer_protocol"] = False
    cfg["cpa_force_standalone"] = False
    cfg["cpa_mint_cookie_inject"] = False
    cfg["cpa_mint_browser_reuse"] = False

    results = []
    with tempfile.TemporaryDirectory(prefix="cpa-reactivate-") as raw_tmp:
        temp_root = Path(raw_tmp)
        temp_auth_dir = temp_root / "cpa_auths"
        temp_auth_dir.mkdir(mode=0o700)
        temp_audit = temp_root / "registration_health_audit.jsonl"
        cfg["cpa_auth_dir"] = str(temp_auth_dir)
        cfg["registration_health_audit_file"] = str(temp_audit)

        import grok_register_ttk as reg
        import cpa_export

        try:
            reg.config.update(cfg)
        except Exception:
            pass

        egress_403 = 0
        for index, account in enumerate(targets, 1):
            label = _safe_label(account.email)
            print(f"[{index}/{len(targets)}] {label}", flush=True)

            def log(message: str, _label=label) -> None:
                safe_message = str(message).replace(account.email, _label)
                print(f"[{_label}] {safe_message}", flush=True)

            row = {"email": label, "_email_key": account.email.lower(), "ok": False}
            try:
                activation = _activate_one(
                    email=account.email,
                    password=account.password,
                    sso=account.sso or "",
                    reg=reg,
                    prefer_sso_inject=True,
                    log=log,
                    cancel=lambda: False,
                )
                row["activation"] = {
                    "ok": bool(activation.get("ok")),
                    "login_method": activation.get("login_method"),
                    "reason": activation.get("reason"),
                }
                if not activation.get("ok"):
                    row["error"] = activation.get("reason") or "activation_failed"
                    continue

                raw_settle = cfg.get("registration_post_activation_settle_sec", 5)
                settle = float(5 if raw_settle is None else raw_settle)
                if settle > 0:
                    time.sleep(settle)
                mint = cpa_export.export_cpa_xai_for_account(
                    email=account.email,
                    password=account.password,
                    page=reg._get_page(),
                    sso=activation.get("sso") or account.sso or "",
                    cookies=activation.get("cookies") or [],
                    config=cfg,
                    log_callback=log,
                )
                health = mint.get("health") if isinstance(mint.get("health"), dict) else {}
                classification = str(health.get("classification") or "unknown")
                row["health"] = {
                    "classification": classification,
                    "confidence": health.get("confidence"),
                    "http_status": health.get("http_status"),
                    "reason": str(health.get("reason") or "")[:240],
                }
                if classification == "healthy" and mint.get("path"):
                    row["ok"] = True
                    row["temp_path"] = str(mint["path"])
                    egress_403 = 0
                else:
                    row["error"] = mint.get("rejection_summary") or mint.get("error") or classification
                    status = int(health.get("http_status") or 0)
                    if status == 403 and classification == "egress_access_denied":
                        egress_403 += 1
                    else:
                        egress_403 = 0
                    if egress_403 >= stop_after_egress_403:
                        row["batch_stopped"] = "consecutive_egress_403"
                        break
            except Exception as exc:  # noqa: BLE001
                row["error"] = f"exception:{exc}"
                egress_403 = 0
            finally:
                results.append(row)
                try:
                    reg.stop_browser()
                except Exception:
                    pass
            if sleep_sec and index < len(targets):
                time.sleep(sleep_sec)

        installed = []
        for row in results:
            if not row.get("ok") or not row.get("temp_path"):
                continue
            temp_path = Path(row["temp_path"])
            email_key = str(row.get("_email_key") or "")
            account = next((a for a in targets if a.email.lower() == email_key), None)
            if account is None or not temp_path.is_file():
                row["ok"] = False
                row["error"] = "healthy_result_missing_source"
                continue
            destination = live_files.get(account.email.lower()) or (live_dir / f"xai-{account.email}.json")
            _atomic_install(temp_path, destination)
            installed.append(_safe_label(account.email))

        summary = {
            "accounts_from_ledgers": len(accounts),
            "target_cpa_accounts": len(targets),
            "duplicate_ledger_rows": duplicates,
            "installed": installed,
            "results": results,
        }
        for row in results:
            row.pop("_email_key", None)
        print(json.dumps(summary, ensure_ascii=False), flush=True)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts", action="append", type=Path, dest="account_files")
    parser.add_argument("--config", type=Path, default=_ROOT / "config.json")
    parser.add_argument("--live-dir", type=Path, default=_ROOT / "cpa_auths")
    parser.add_argument("--sleep", type=float, default=5.0)
    parser.add_argument("--max-accounts", type=int, default=0)
    args = parser.parse_args()
    files = args.account_files or _default_account_files()
    summary = run(
        account_files=files,
        config_path=args.config,
        live_dir=args.live_dir,
        sleep_sec=max(0.0, args.sleep),
        max_accounts=max(0, args.max_accounts),
    )
    return 0 if summary["installed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
