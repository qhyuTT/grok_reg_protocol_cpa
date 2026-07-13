"""Locate a Chromium/Chrome binary on Linux, macOS, and Windows."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def candidate_browser_paths() -> list[str]:
    """Ordered list of likely browser executables for this OS."""
    found: list[str] = []
    seen: set[str] = set()

    def add(path: str | None) -> None:
        if not path:
            return
        p = os.path.normpath(path)
        if p in seen:
            return
        seen.add(p)
        found.append(p)

    # PATH first (works when chrome/chromium is installed as a command)
    for name in (
        "chrome",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "msedge",
    ):
        add(shutil.which(name))

    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        for base in (local, pf, pf86):
            if not base:
                continue
            add(str(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe"))
            add(str(Path(base) / "Chromium" / "Application" / "chrome.exe"))
            add(str(Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"))
    elif sys.platform == "darwin":
        add("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        add("/Applications/Chromium.app/Contents/MacOS/Chromium")
        add("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
    else:
        for cand in (
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
        ):
            add(cand)

    return found


def resolve_browser_path() -> str | None:
    """Return first existing browser path, or None to let DrissionPage auto-detect."""
    for cand in candidate_browser_paths():
        if os.path.isfile(cand):
            return cand
    return None


def apply_browser_path(opts) -> str | None:
    """Set browser path on ChromiumOptions if a binary is found. Returns path or None."""
    path = resolve_browser_path()
    if not path:
        return None
    try:
        opts.set_browser_path(path)
    except Exception:
        return None
    return path
