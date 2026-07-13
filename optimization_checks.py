#!/usr/bin/env python3
"""optimization_checks.py — static health checks for register + CPA pipeline.

Usage: uv run python optimization_checks.py
Exit: 0=all pass, 1=any fail

Checks code contracts (imports, APIs, config template keys) — not live network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
CHECKS: list[tuple[str, Callable[[], bool]]] = []


def check(name: str):
    def decorator(func: Callable[[], bool]):
        CHECKS.append((name, func))
        return func

    return decorator


def _source(filename: str) -> str:
    return (ROOT / filename).read_text(encoding="utf-8")


def _example_config() -> dict:
    raw = json.loads(_source("config.example.json"))
    # strip // comment keys
    return {k: v for k, v in raw.items() if not str(k).startswith("//") and not str(k).startswith("#")}


# ── 1. deps / toolchain ──

@check("pyproject-deps")
def check_deps() -> bool:
    src = _source("pyproject.toml")
    return "DrissionPage" in src and "curl_cffi" in src


@check("config-example-cpa-keys")
def check_config_keys() -> bool:
    conf = _example_config()
    required = (
        "cpa_export_enabled",
        "cpa_prefer_protocol",
        "cpa_protocol_only",
        "cpa_auth_dir",
        "cpa_base_url",
        "cpa_mint_workers",
    )
    return all(k in conf for k in required)


# ── 2. browser / tab isolation ──

@check("tab-pool-thread-local")
def check_tab_pool() -> bool:
    src = _source("tab_pool.py")
    return "threading.local" in src and "clear_session" in src


@check("chromium-paths-cross-platform")
def check_chromium_paths() -> bool:
    src = _source("chromium_paths.py")
    return "win32" in src and "apply_browser_path" in src


@check("cli-uses-chromium-paths")
def check_cli_browser_paths() -> bool:
    src = _source("register_cli.py")
    return "chromium_paths" in src and "apply_browser_path" in src


# ── 3. CPA protocol pipeline ──

@check("protocol-mint-module")
def check_protocol_mint() -> bool:
    src = _source("cpa_xai/protocol_mint.py")
    return "mint_with_sso_protocol" in src and "curl_cffi" in src


@check("oauth-prefers-curl-cffi")
def check_oauth_curl() -> bool:
    src = _source("cpa_xai/oauth_device.py")
    return "_post_form_curl" in src and "impersonate" in src


@check("mint-error-codes")
def check_error_codes() -> bool:
    src = _source("cpa_xai/mint.py")
    err = _source("cpa_xai/errors.py")
    return "error_code" in src and "classify_protocol_message" in err


@check("export-failure-jsonl")
def check_export_jsonl() -> bool:
    src = _source("cpa_export.py")
    return "cpa_auth_failed.jsonl" in src and "error_code" in src


# ── 4. CLI pipeline ──

@check("multi-thread-worker")
def check_multi_thread() -> bool:
    src = _source("register_cli.py")
    return "threading.Thread" in src and "mint_queue" in src


@check("mint-worker-resolve")
def check_mint_resolve() -> bool:
    src = _source("register_cli.py")
    return "resolve_mint_workers" in src and "cpa_mint_workers" in src


@check("resume-checkpoint")
def check_resume() -> bool:
    src = _source("register_cli.py")
    return "done_count" in src


@check("error-isolation")
def check_error_isolation() -> bool:
    src = _source("register_cli.py")
    return "reg_fail" in src and "retry" in src.lower()


# ── 5. register ergonomics ──

@check("human-sleep")
def check_human_sleep() -> bool:
    src = _source("grok_register_ttk.py")
    return "def human_sleep" in src


@check("browser-recycle")
def check_browser_recycle() -> bool:
    src = _source("register_cli.py")
    return "browser_recycle_every" in src or "recycle_every" in src


def main() -> int:
    fail_count = 0
    for name, func in CHECKS:
        try:
            ok = func()
        except Exception as exc:
            print(f"FAIL  {name}: exception={exc}")
            fail_count += 1
            continue
        if ok:
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}")
            fail_count += 1

    total = len(CHECKS)
    print(f"\n--- {total - fail_count}/{total} pass, {fail_count} fail ---")
    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
