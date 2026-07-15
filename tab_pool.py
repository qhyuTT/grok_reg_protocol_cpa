#!/usr/bin/env python3
"""TabPool — per-thread Chromium with proper lifecycle.

Interface:
    TabPool.init(options_factory) → save options factory (no browser yet)
    TabPool.get_tab()             → get/create current thread browser tab
    TabPool.clear_session()       → wipe cookies/storage; keep process warm
    TabPool.release_tab()         → quit current thread browser + drop registry
    TabPool.shutdown()            → quit all known browsers

Notes:
    - One Chromium per worker thread (cookie isolation).
    - Default callers close per account; explicit reuse uses clear_session().
    - _all_browsers is pruned on release to avoid zombie list growth.
"""

from __future__ import annotations

import threading
from typing import Any

from browser_lifecycle import cleanup_failed_browser_start, close_owned_browser


class TabPool:
    """Per-thread Chromium instance manager."""

    _options_factory = None
    _options_lock = threading.Lock()
    _thread_local = threading.local()
    _all_browsers: list[Any] = []
    _all_browsers_lock = threading.Lock()
    _lifecycle_lock = threading.RLock()
    _accept_new = True
    _permanent_block = False
    _failed_closes: set[int] = set()
    _lifecycle_observer: Any = None

    # ── public ──

    @classmethod
    def init(cls, browser_options_or_factory, log_callback=None):
        """Save options object or factory. Callable → fresh options each create."""
        with cls._options_lock:
            if callable(browser_options_or_factory):
                cls._options_factory = browser_options_or_factory
            else:
                # Shared options object: auto_port will NOT re-allocate.
                cls._options_factory = lambda: browser_options_or_factory
        if log_callback:
            log_callback("[*] TabPool 已初始化浏览器选项模板")

    @classmethod
    def set_lifecycle_observer(cls, observer: Any = None) -> None:
        """Install an optional browser observer used by diagnostic tracing."""
        with cls._lifecycle_lock:
            cls._lifecycle_observer = observer

    @classmethod
    def _notify_browser_ready(cls, browser: Any, tab: Any) -> None:
        observer = cls._lifecycle_observer
        if observer is None:
            return
        try:
            observer.browser_ready(browser, tab)
        except Exception:
            pass

    @classmethod
    def _notify_browser_releasing(cls, browser: Any, tab: Any) -> None:
        observer = cls._lifecycle_observer
        if observer is None:
            return
        try:
            observer.browser_releasing(browser, tab)
        except Exception:
            pass

    @classmethod
    def _create_browser(cls):
        from DrissionPage import Chromium

        with cls._lifecycle_lock:
            if not cls._accept_new:
                raise RuntimeError("browser creation disabled during shutdown")
            with cls._options_lock:
                factory = cls._options_factory
            if factory is None:
                return None
            options = factory()
            try:
                browser = Chromium(options)
            except BaseException:  # noqa: BLE001
                cleanup_failed_browser_start(options)
                raise
            with cls._all_browsers_lock:
                cls._all_browsers.append(browser)
            return browser

    @classmethod
    def allow_new(cls) -> None:
        """Allow a new batch to create browsers after a non-permanent shutdown."""
        with cls._lifecycle_lock:
            with cls._all_browsers_lock:
                remaining = len(cls._all_browsers)
            if remaining:
                raise RuntimeError(
                    f"cannot enable browser creation while {remaining} Chromium instance(s) remain"
                )
            cls._failed_closes.clear()
            cls._permanent_block = False
            cls._accept_new = True

    @classmethod
    def _unregister(cls, browser) -> None:
        if browser is None:
            return
        with cls._all_browsers_lock:
            try:
                cls._all_browsers = [b for b in cls._all_browsers if b is not browser]
            except Exception:
                pass

    @classmethod
    def _is_registered(cls, browser) -> bool:
        with cls._all_browsers_lock:
            return any(item is browser for item in cls._all_browsers)

    @classmethod
    def get_tab(cls, url=None):
        """Return current thread tab; create Chromium on first use."""
        tab = getattr(cls._thread_local, "tab", None)
        if tab is not None:
            browser = getattr(cls._thread_local, "browser", None)
            if browser is not None:
                cls._notify_browser_ready(browser, tab)
            return tab
        stale_browser = getattr(cls._thread_local, "browser", None)
        if stale_browser is not None and not cls.release_tab():
            raise RuntimeError("previous Chromium could not be closed; refusing to create another")
        browser = cls._create_browser()
        if browser is None:
            raise RuntimeError("TabPool not initialized — call init() first")
        # Bind ownership before touching tabs. Browser startup may succeed while
        # the first CDP/tab lookup fails; release_tab() must still be able to
        # find and close that process.
        cls._thread_local.browser = browser
        cls._thread_local.tab = None
        cls._thread_local.served = 0
        try:
            tab_ids = browser.tab_ids
            if tab_ids:
                tab = browser.get_tab(tab_ids[0])
            else:
                tab = browser.new_tab()
            cls._thread_local.tab = tab
            cls._notify_browser_ready(browser, tab)
            return tab
        except BaseException:  # noqa: BLE001
            cls.release_tab()
            raise

    @classmethod
    def sync_tab(cls):
        """Point thread-local tab at the browser's latest tab."""
        browser = getattr(cls._thread_local, "browser", None)
        if browser is None:
            return
        tabs = browser.tab_ids
        if tabs:
            cls._thread_local.tab = browser.get_tab(tabs[-1])

    @classmethod
    def clear_session(cls, log_callback=None) -> bool:
        """Clear cookies/storage and blank the page; keep Chromium process.

        Returns True if session was cleared on a live browser; False if no browser.
        """
        browser = getattr(cls._thread_local, "browser", None)
        tab = getattr(cls._thread_local, "tab", None)
        if browser is None:
            return False
        ok = True
        try:
            if tab is not None:
                try:
                    tab.get("about:blank")
                except Exception:
                    pass
                for js in (
                    "try{localStorage.clear()}catch(e){}",
                    "try{sessionStorage.clear()}catch(e){}",
                    "try{indexedDB.databases&&indexedDB.databases().then(ds=>ds.forEach(d=>indexedDB.deleteDatabase(d.name)))}catch(e){}",
                ):
                    try:
                        tab.run_js(js)
                    except Exception:
                        pass
            # Best-effort cookie wipe (API varies by DrissionPage version)
            cleared = False
            for target in (tab, browser):
                if target is None or cleared:
                    continue
                for attr_path in (
                    ("set", "cookies", "clear"),
                    ("cookies", "clear"),
                ):
                    try:
                        obj = target
                        for name in attr_path[:-1]:
                            obj = getattr(obj, name)
                        fn = getattr(obj, attr_path[-1])
                        fn()
                        cleared = True
                        break
                    except Exception:
                        continue
            if not cleared:
                try:
                    # Fallback: drop all cookies via CDP-ish helper if present
                    cks = browser.cookies()
                    if isinstance(cks, list):
                        for c in cks:
                            try:
                                browser.set.cookies.remove(c)  # type: ignore[attr-defined]
                            except Exception:
                                pass
                except Exception:
                    ok = False
            # Prefer a single clean tab
            try:
                tabs = list(browser.tab_ids or [])
                if len(tabs) > 1:
                    keep = tabs[0]
                    for tid in tabs[1:]:
                        try:
                            browser.get_tab(tid).close()
                        except Exception:
                            pass
                    cls._thread_local.tab = browser.get_tab(keep)
                elif tabs:
                    cls._thread_local.tab = browser.get_tab(tabs[0])
            except Exception:
                cls.sync_tab()
            if log_callback:
                served = int(getattr(cls._thread_local, "served", 0) or 0)
                log_callback(f"[*] 浏览器会话已清理（复用进程, served={served}）")
            return ok
        except Exception as exc:
            if log_callback:
                log_callback(f"[!] clear_session 失败: {exc}")
            return False

    @classmethod
    def mark_served(cls) -> int:
        n = int(getattr(cls._thread_local, "served", 0) or 0) + 1
        cls._thread_local.served = n
        return n

    @classmethod
    def served_count(cls) -> int:
        return int(getattr(cls._thread_local, "served", 0) or 0)

    @classmethod
    def release_tab(cls) -> bool:
        """Quit current thread Chromium and unregister it when confirmed closed."""
        with cls._lifecycle_lock:
            browser = getattr(cls._thread_local, "browser", None)
            tab = getattr(cls._thread_local, "tab", None)
            closed = True
            if browser is not None and cls._is_registered(browser):
                cls._notify_browser_releasing(browser, tab)
                closed = close_owned_browser(browser)
                if closed:
                    cls._failed_closes.discard(id(browser))
                    cls._unregister(browser)
            if closed:
                cls._thread_local.browser = None
                cls._thread_local.served = 0
                if not cls._permanent_block and not cls._failed_closes:
                    cls._accept_new = True
            else:
                # Keep ownership so the next get_tab() retries cleanup instead
                # of silently creating another Chromium alongside it.
                cls._thread_local.browser = browser
                cls._failed_closes.add(id(browser))
                cls._accept_new = False
            cls._thread_local.tab = None
            return closed

    @classmethod
    def refresh_tab(cls):
        """Full recycle: quit + new browser."""
        cls.release_tab()
        return cls.get_tab()

    @classmethod
    def shutdown(cls, *, block_new: bool = False):
        """Quit every browser we still track."""
        with cls._lifecycle_lock:
            if block_new:
                cls._permanent_block = True
                cls._accept_new = False
            with cls._all_browsers_lock:
                browsers = list(cls._all_browsers)
            for browser in browsers:
                if close_owned_browser(browser):
                    cls._failed_closes.discard(id(browser))
                    cls._unregister(browser)
                else:
                    cls._failed_closes.add(id(browser))
            if not cls._permanent_block:
                cls._accept_new = not cls._failed_closes
            current = getattr(cls._thread_local, "browser", None)
            if current is not None and not cls._is_registered(current):
                cls._thread_local.browser = None
                cls._thread_local.tab = None
                cls._thread_local.served = 0

    @classmethod
    def live_count(cls) -> int:
        with cls._all_browsers_lock:
            return len(cls._all_browsers)

    @classmethod
    def get_browser(cls):
        return getattr(cls._thread_local, "browser", None)
