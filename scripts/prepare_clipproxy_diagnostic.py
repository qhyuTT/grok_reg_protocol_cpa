#!/usr/bin/env python3
"""Prepare an isolated single-credential CLIProxyAPI diagnostic directory."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = Path("/tmp/cliproxyapi-xai-diagnostic")


def _load_project_config(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"project config not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid project config: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("project config must be a JSON object")
    return data


def _parse_expiry(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _validate_auth(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid auth JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("type") != "xai":
        raise SystemExit("diagnostic auth must be a CPA xai JSON file")
    if payload.get("disabled") is True:
        raise SystemExit("diagnostic auth is disabled")
    expiry = _parse_expiry(payload.get("expired"))
    if expiry is not None and expiry <= datetime.now(timezone.utc):
        raise SystemExit(f"diagnostic auth expired at {expiry.isoformat()}")
    if not payload.get("access_token") or not payload.get("refresh_token"):
        raise SystemExit("diagnostic auth is missing access_token or refresh_token")
    return payload


def _yaml_string(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def prepare(
    *,
    project_config: Path,
    output_dir: Path,
    port: int,
    source_auth: Path | None,
) -> dict[str, Path | int | bool]:
    cfg = _load_project_config(project_config)
    registration_proxy = str(cfg.get("proxy") or "").strip()
    cpa_proxy = str(cfg.get("cpa_proxy") or "").strip()
    if registration_proxy and cpa_proxy and registration_proxy != cpa_proxy:
        raise SystemExit(
            "proxy and cpa_proxy differ; diagnostic requires the same registration/CPA egress"
        )
    proxy = cpa_proxy or registration_proxy
    if not proxy:
        raise SystemExit("cpa_proxy/proxy is empty; diagnostic egress must be explicit")

    output_dir = output_dir.expanduser().resolve()
    auth_dir = output_dir / "auth"
    output_dir.mkdir(parents=True, exist_ok=True)
    auth_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(output_dir, 0o700)
    os.chmod(auth_dir, 0o700)

    for old in auth_dir.glob("*.json"):
        old.unlink()

    copied_auth = False
    if source_auth is not None:
        source_auth = source_auth.expanduser().resolve()
        if not source_auth.is_file():
            raise SystemExit(f"auth file not found: {source_auth}")
        _validate_auth(source_auth)
        destination = auth_dir / source_auth.name
        shutil.copy2(source_auth, destination)
        os.chmod(destination, 0o600)
        copied_auth = True

    api_key = "diag-" + secrets.token_urlsafe(24)
    key_path = output_dir / "api_key.txt"
    key_path.write_text(api_key + "\n", encoding="utf-8")
    os.chmod(key_path, 0o600)

    config_path = output_dir / "config.yaml"
    config_text = f"""host: \"127.0.0.1\"
port: {int(port)}

tls:
  enable: false

remote-management:
  allow-remote: false
  secret-key: \"\"
  disable-control-panel: true
  disable-auto-update-panel: true

auth-dir: {_yaml_string(str(auth_dir))}
api-keys:
  - {_yaml_string(api_key)}

debug: false
logging-to-file: false
usage-statistics-enabled: false
proxy-url: {_yaml_string(proxy)}
request-retry: 0
max-retry-credentials: 1
max-retry-interval: 0
"""
    config_path.write_text(config_text, encoding="utf-8")
    os.chmod(config_path, 0o600)

    return {
        "output_dir": output_dir,
        "auth_dir": auth_dir,
        "config_path": config_path,
        "key_path": key_path,
        "port": int(port),
        "copied_auth": copied_auth,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare an isolated CLIProxyAPI config with one credential and no retry fan-out."
    )
    parser.add_argument(
        "--project-config",
        type=Path,
        default=PROJECT_ROOT / "config.json",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--port", type=int, default=18317)
    parser.add_argument("--source-auth", type=Path)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    result = prepare(
        project_config=args.project_config,
        output_dir=args.output_dir,
        port=args.port,
        source_auth=args.source_auth,
    )
    print(f"diagnostic_dir={result['output_dir']}")
    print(f"config={result['config_path']}")
    print(f"auth_dir={result['auth_dir']} auth_count={1 if result['copied_auth'] else 0}")
    print(f"api_key_file={result['key_path']}")
    print(f"port={result['port']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
