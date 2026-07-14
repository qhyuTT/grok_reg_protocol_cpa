"""Reliable shutdown helpers for Chromium instances owned by this process."""

from __future__ import annotations

import os
import re
from typing import Any, Callable

import psutil

LogFn = Callable[[str], None]


def _log(log_callback: LogFn | None, message: str) -> None:
    if log_callback:
        try:
            log_callback(message)
        except Exception:
            pass


def _same_process(process: psutil.Process, create_time: float | None) -> bool:
    try:
        if create_time is not None and process.create_time() != create_time:
            return False
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except psutil.Error:
        return True


def _debug_port(address: str) -> int:
    match = re.search(r":(\d+)$", address)
    return int(match.group(1)) if match else 0


def _profile_arg_matches(arguments: list[str], user_data: str) -> bool:
    if not user_data:
        return False
    expected = os.path.realpath(user_data)
    for argument in arguments:
        if argument.startswith("--user-data-dir="):
            actual = argument.split("=", 1)[1]
            return os.path.realpath(actual) == expected
    return False


def _is_owned_browser_process(process: psutil.Process, browser: Any) -> bool:
    """Verify OS-signal ownership instead of blindly trusting process_id."""
    try:
        if process.ppid() != os.getpid():
            return False
        arguments = process.cmdline()
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        return False
    if not arguments:
        return False
    address = str(getattr(browser, "address", "") or "")
    port = _debug_port(address)
    user_data = str(getattr(browser, "user_data_path", "") or "")
    has_port = bool(port and f"--remote-debugging-port={port}" in arguments)
    has_profile = _profile_arg_matches(arguments, user_data)
    # Both independently assigned DrissionPage identifiers must match exactly.
    # This prevents an incorrect process_id from authorizing an unrelated child.
    return has_port and has_profile and "DrissionPage/autoPortData" in user_data


def cleanup_failed_browser_start(
    options: Any,
    *,
    log_callback: LogFn | None = None,
    timeout: float = 3.0,
) -> int:
    """Reap a direct child Chrome left behind when ``Chromium(options)`` raises."""
    address = str(getattr(options, "address", "") or "")
    port = _debug_port(address)
    user_data = str(getattr(options, "user_data_path", "") or "")
    if not port and not user_data:
        return 0

    try:
        children = psutil.Process(os.getpid()).children(recursive=False)
    except psutil.Error:
        return 0

    candidates: list[psutil.Process] = []
    for process in children:
        try:
            arguments = process.cmdline()
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue
        has_port = bool(port and f"--remote-debugging-port={port}" in arguments)
        has_profile = _profile_arg_matches(arguments, user_data)
        command = " ".join(arguments)
        if (has_port or has_profile) and "DrissionPage/autoPortData" in command:
            candidates.append(process)

    for process in candidates:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.Error as exc:
            _log(log_callback, f"[!] 启动失败浏览器 terminate 异常 PID={process.pid}: {exc}")

    _gone, alive = psutil.wait_procs(candidates, timeout=max(0.2, float(timeout)))
    for process in alive:
        try:
            process.kill()
        except psutil.NoSuchProcess:
            continue
        except psutil.Error as exc:
            _log(log_callback, f"[!] 启动失败浏览器 kill 异常 PID={process.pid}: {exc}")
    if alive:
        psutil.wait_procs(alive, timeout=2.0)
    if candidates:
        _log(log_callback, f"[*] 已回收启动失败的 Chromium: {[p.pid for p in candidates]}")
    return len(candidates)


def close_owned_browser(
    browser: Any,
    *,
    log_callback: LogFn | None = None,
    timeout: float = 5.0,
) -> bool:
    """Close one owned Chromium and verify its browser PID exits.

    DrissionPage's normal ``Browser.close`` may disconnect without actually
    terminating Chrome. Capture the exact browser PID before quit, then use a
    bounded terminate/kill fallback only for that same process instance.
    """
    if browser is None:
        return True

    address = str(getattr(browser, "address", "") or "")
    try:
        pid = int(getattr(browser, "process_id", 0) or 0)
    except (TypeError, ValueError):
        pid = 0

    process = None
    create_time = None
    if pid > 0:
        try:
            process = psutil.Process(pid)
            create_time = process.create_time()
        except psutil.NoSuchProcess:
            process = None
        except psutil.Error as exc:
            _log(log_callback, f"[!] 无法检查浏览器 PID={pid}: {exc}")

    quit_error: BaseException | None = None
    try:
        browser.quit(timeout=max(1, int(timeout)), force=True, del_data=True)
    except TypeError:
        try:
            browser.quit()
        except BaseException as exc:  # noqa: BLE001
            quit_error = exc
    except BaseException as exc:  # noqa: BLE001
        quit_error = exc

    if quit_error is not None:
        _log(
            log_callback,
            f"[!] Chromium quit 异常 PID={pid or '?'} address={address or '?'}: {quit_error}",
        )

    if process is None:
        # Mocks/remote browsers may not expose a local process id. In that case
        # the quit call is the only available source of truth.
        return quit_error is None

    graceful_wait = max(0.2, min(float(timeout), 2.0))
    try:
        process.wait(timeout=graceful_wait)
        _log(log_callback, f"[*] Chromium 已退出 PID={pid}")
        return True
    except psutil.NoSuchProcess:
        return True
    except psutil.TimeoutExpired:
        pass
    except psutil.Error as exc:
        _log(log_callback, f"[!] 等待 Chromium 退出失败 PID={pid}: {exc}")

    if not _same_process(process, create_time):
        return True

    if not _is_owned_browser_process(process, browser):
        _log(
            log_callback,
            f"[!] 拒绝强制终止未验证归属的 PID={pid} address={address or '?'}",
        )
        return False

    try:
        process.terminate()
        process.wait(timeout=max(0.5, float(timeout) - graceful_wait))
        _log(log_callback, f"[*] Chromium 已强制终止 PID={pid}")
        return True
    except psutil.NoSuchProcess:
        return True
    except psutil.TimeoutExpired:
        pass
    except psutil.Error as exc:
        _log(log_callback, f"[!] Chromium terminate 失败 PID={pid}: {exc}")

    if not _same_process(process, create_time):
        return True

    try:
        process.kill()
        process.wait(timeout=2.0)
        _log(log_callback, f"[*] Chromium 已杀死 PID={pid}")
        return True
    except psutil.NoSuchProcess:
        return True
    except psutil.Error as exc:
        _log(log_callback, f"[!] Chromium kill 失败 PID={pid}: {exc}")
        return not _same_process(process, create_time)
