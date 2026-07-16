#!/usr/bin/env python3
"""Batch mint CPA xai-*.json from register accounts_cli.txt.

Uses the same export path as registration (`cpa_export.export_cpa_xai_for_account`),
so config-driven health gate / audit / protocol-first mint all apply.

Example (from project root):
  uv run python -u scripts/backfill_cpa_xai_from_accounts.py \\
    --accounts accounts_20260713_231340.txt \\
    --limit 2 --no-skip-existing
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
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


def _cpa_path_for_email(auth_dir: Path, email: str) -> Path:
    return auth_dir / f"xai-{email}.json"


def _delete_cpa_if_present(auth_dir: Path, email: str, log) -> None:
    path = _cpa_path_for_email(auth_dir, email)
    if not path.is_file():
        return
    try:
        path.unlink()
        log(f"removed rejected CPA file: {path}")
    except OSError as exc:
        log(f"failed to remove rejected CPA file {path}: {exc}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--accounts",
        default=str(_ROOT / "accounts_cli.txt"),
    )
    ap.add_argument(
        "--out-dir",
        default="",
        help="Override config cpa_auth_dir (default: config or cpa_auths)",
    )
    ap.add_argument(
        "--cpa-dir",
        default="",
        help="Optional CPA hot-load auth-dir; files are copied here after success",
    )
    ap.add_argument("--limit", type=int, default=0, help="0 = all missing")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--email", default="", help="Only this email")
    ap.add_argument("--skip-existing", action="store_true", default=True)
    ap.add_argument("--no-skip-existing", action="store_false", dest="skip_existing")
    ap.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Headless Chromium (usually blocked by Cloudflare on accounts.x.ai)",
    )
    ap.add_argument(
        "--headed",
        action="store_true",
        default=True,
        help="Show browser (default; required for stable device consent)",
    )
    ap.add_argument("--probe", action="store_true", default=True)
    ap.add_argument("--no-probe", action="store_false", dest="probe")
    ap.add_argument("--probe-chat", action="store_true", default=False)
    ap.add_argument(
        "--no-health-check",
        action="store_true",
        default=False,
        help="Force registration_health_check_enabled=false for this run",
    )
    ap.add_argument(
        "--proxy",
        default="",
        help="Outbound proxy. Empty → read register config.json cpa_proxy/proxy, else env",
    )
    ap.add_argument(
        "--config",
        default=str(_ROOT / "config.json"),
        help="register config.json for health gate / proxy / cpa dirs",
    )
    ap.add_argument("--timeout", type=float, default=0.0, help="0 = use config cpa_mint_timeout_sec")
    ap.add_argument("--sleep", type=float, default=3.0, help="Sleep between accounts")
    ap.add_argument(
        "--fail-log",
        default=str(_ROOT / "cpa_auths" / "backfill_failed.jsonl"),
        help="Append failures JSONL",
    )
    ap.add_argument(
        "--force-standalone",
        action="store_true",
        default=True,
        help="Always open fresh Chromium (default)",
    )
    args = ap.parse_args()

    if args.headless:
        args.headed = False
    else:
        args.headless = False

    cfg = _load_config(Path(args.config))
    if args.proxy:
        cfg["cpa_proxy"] = args.proxy.strip()
        cfg["proxy"] = args.proxy.strip()
    if args.out_dir:
        cfg["cpa_auth_dir"] = args.out_dir
    if args.cpa_dir:
        cfg["cpa_hotload_dir"] = args.cpa_dir
        cfg["cpa_copy_to_hotload"] = True
    if args.timeout and args.timeout > 0:
        cfg["cpa_mint_timeout_sec"] = args.timeout
    cfg["cpa_headless"] = bool(args.headless)
    cfg["cpa_probe_after_write"] = bool(args.probe)
    cfg["cpa_probe_chat"] = bool(args.probe_chat)
    cfg["cpa_force_standalone"] = bool(args.force_standalone)
    if args.no_health_check:
        cfg["registration_health_check_enabled"] = False

    # Resolve display paths for logging / skip-existing
    out_raw = (cfg.get("cpa_auth_dir") or str(_ROOT / "cpa_auths")).strip()
    out_dir = Path(out_raw).expanduser()
    if not out_dir.is_absolute():
        out_dir = (_ROOT / out_dir).resolve()
    hot_raw = (cfg.get("cpa_hotload_dir") or "").strip()
    cpa_dir = Path(hot_raw).expanduser() if hot_raw else None
    if cpa_dir and not cpa_dir.is_absolute():
        cpa_dir = (_ROOT / cpa_dir).resolve()

    proxy = (cfg.get("cpa_proxy") or cfg.get("proxy") or "").strip()
    if not proxy:
        proxy = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or ""
        ).strip()
        if proxy:
            cfg["cpa_proxy"] = proxy

    health_on = bool(cfg.get("registration_health_check_enabled", False))
    print(f"proxy={proxy or '(none)'}", flush=True)
    print(
        f"health_check={health_on} delays={cfg.get('registration_health_probe_delays_sec', [0, 15, 45])}",
        flush=True,
    )

    accounts = parse_accounts_file(args.accounts)
    if args.email:
        accounts = [a for a in accounts if a.email.lower() == args.email.lower()]
    accounts = accounts[args.offset :]

    have: set[str] = set()
    if args.skip_existing:
        have |= {e.lower() for e in existing_cpa_emails(out_dir)}
        if cpa_dir:
            have |= {e.lower() for e in existing_cpa_emails(cpa_dir)}

    todo = []
    for a in accounts:
        if args.skip_existing and a.email.lower() in have:
            continue
        todo.append(a)
        if args.limit and len(todo) >= args.limit:
            break

    print(
        f"accounts total={len(parse_accounts_file(args.accounts))} "
        f"todo={len(todo)} out={out_dir} health={health_on}",
        flush=True,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    if cpa_dir:
        cpa_dir.mkdir(parents=True, exist_ok=True)

    import cpa_export

    ok_n = rejected_n = fail_n = skip_n = 0
    results: list[dict] = []
    for i, acc in enumerate(todo, 1):
        print(f"\n=== [{i}/{len(todo)}] {acc.email} ===", flush=True)

        def log(msg: str, _email=acc.email) -> None:
            print(f"[{time.strftime('%H:%M:%S')}] [{_email}] {msg}", flush=True)

        r = cpa_export.export_cpa_xai_for_account(
            email=acc.email,
            password=acc.password,
            sso=acc.sso or "",
            config=cfg,
            log_callback=log,
        )
        # Normalize path key used by summary/copy
        if r.get("path") and not r.get("cpa_path"):
            pass
        results.append(r)

        health = r.get("health") if isinstance(r.get("health"), dict) else {}
        classification = health.get("classification") if health else None

        if r.get("skipped"):
            skip_n += 1
            log(f"skipped: {r.get('reason') or r.get('error')}")
        elif r.get("rejected"):
            rejected_n += 1
            _delete_cpa_if_present(out_dir, acc.email, log)
            if cpa_dir:
                _delete_cpa_if_present(cpa_dir, acc.email, log)
            log(
                f"REJECTED classification={classification} "
                f"summary={r.get('rejection_summary') or r.get('error')}"
            )
            if args.fail_log:
                Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                with open(args.fail_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
        elif r.get("ok") and r.get("path"):
            ok_n += 1
            log(
                f"OK path={r.get('path')} health={classification or 'n/a'} "
                f"method={r.get('mint_method')}"
            )
            if cpa_dir and cfg.get("cpa_copy_to_hotload", False):
                src = Path(r["path"])
                if src.is_file():
                    dst = cpa_dir / src.name
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o600)
                    print(f"copied -> {dst}", flush=True)
        elif r.get("ok"):
            # health-only export disabled
            ok_n += 1
            log(f"OK health-only classification={classification or 'n/a'}")
        else:
            fail_n += 1
            log(f"FAIL: {r.get('error') or r}")
            if args.fail_log:
                Path(args.fail_log).parent.mkdir(parents=True, exist_ok=True)
                with open(args.fail_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")

        if args.sleep and i < len(todo):
            time.sleep(args.sleep)

    print(
        f"\n=== done ok={ok_n} rejected={rejected_n} fail={fail_n} skip={skip_n} ===",
        flush=True,
    )
    summary = out_dir / f"backfill_summary_{int(time.time())}.json"
    summary.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"summary {summary}")
    # Success if at least one ok, or nothing to do; pure reject/fail batch exits 1
    if not todo:
        return 0
    return 0 if ok_n > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
