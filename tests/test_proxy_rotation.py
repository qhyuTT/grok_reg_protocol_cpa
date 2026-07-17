#!/usr/bin/env python3
"""Unit tests for proxy_rotation (mock Clash controller, no live network)."""

from __future__ import annotations

import json
import hashlib
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import unquote

import proxy_rotation as pr


class _FakeClashHandler(BaseHTTPRequestHandler):
    """Minimal Clash Meta controller fake."""

    state: dict = {
        "group": "飞鸟云",
        "now": "美国03aws",
        "all": [
            "自动选择",
            "故障转移",
            "剩余流量：45.15 GB",
            "新加坡03aws",
            "美国02aws",
            "美国03aws",
            "美国04aws",
            "日本01aws",
            "vless美国01",
        ],
        "secret": "test-secret",
        "fail_switch": False,
    }

    def log_message(self, format, *args):  # noqa: A003
        return

    def _auth_ok(self) -> bool:
        secret = self.state.get("secret") or ""
        if not secret:
            return True
        auth = self.headers.get("Authorization") or ""
        return auth == f"Bearer {secret}"

    def do_GET(self):  # noqa: N802
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/version":
            self._json(200, {"version": "fake", "meta": True})
            return
        if self.path.startswith("/proxies/"):
            name = unquote(self.path[len("/proxies/") :])
            if name != self.state["group"]:
                self._json(404, {"message": "not found"})
                return
            self._json(
                200,
                {
                    "name": name,
                    "type": "Selector",
                    "now": self.state["now"],
                    "all": list(self.state["all"]),
                },
            )
            return
        self._json(404, {"message": "nope"})

    def do_PUT(self):  # noqa: N802
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {}
        if self.path.startswith("/proxies/"):
            if self.state.get("fail_switch"):
                self._json(400, {"message": "fail"})
                return
            node = str(data.get("name") or "")
            if node:
                self.state["now"] = node
            self.send_response(204)
            self.end_headers()
            return
        self._json(404, {})

    def _json(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ProxyRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), _FakeClashHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        _FakeClashHandler.state["now"] = "美国03aws"
        _FakeClashHandler.state["fail_switch"] = False
        _FakeClashHandler.state["secret"] = "test-secret"
        # reset singleton
        pr._manager = None
        pr._manager_sig = None

    def _cfg(self, tmp: Path, **extra) -> dict:
        base = {
            "proxy_rotation_enabled": True,
            "proxy_rotation_controller_url": f"http://127.0.0.1:{self.port}",
            "proxy_rotation_controller_secret": "test-secret",
            "proxy_rotation_proxy_group": "飞鸟云",
            "proxy_rotation_node_filter": r"(?i)美国",
            "proxy_rotation_node_exclude": r"(?i)自动选择|故障转移|剩余流量|套餐到期|新加坡|日本|台湾",
            "proxy": "http://127.0.0.1:7890",
            "cpa_proxy": "http://127.0.0.1:7890",
            "proxy_rotation_gateway": "http://127.0.0.1:7890",
            "proxy_rotation_switch_settle_sec": 0,
            "proxy_rotation_switch_confirm_timeout_sec": 0.2,
            "proxy_rotation_switch_confirm_interval_sec": 0,
            "proxy_rotation_max_switch_attempts": 5,
            "proxy_rotation_max_wait_sec": 0,
            "proxy_rotation_cooldown_healthy_sec": 360,
            "proxy_rotation_cooldown_denied_sec": 900,
            "proxy_rotation_cooldown_forbidden_unknown_sec": 180,
            "proxy_rotation_require_us": True,
            "proxy_rotation_state_file": str(tmp / "state.json"),
        }
        base.update(extra)
        return base

    def test_controller_lists_and_filters_us(self):
        c = pr.ClashController(
            f"http://127.0.0.1:{self.port}", secret="test-secret", timeout=2
        )
        now, all_names = c.list_group_nodes("飞鸟云")
        self.assertEqual(now, "美国03aws")
        self.assertIn("美国02aws", all_names)
        mgr = pr.EgressLeaseManager(self._cfg(Path("/tmp")))
        us = mgr._filter_nodes(all_names)
        self.assertIn("美国02aws", us)
        self.assertIn("vless美国01", us)
        self.assertNotIn("新加坡03aws", us)
        self.assertNotIn("自动选择", us)

    def test_switch_sends_put_and_secret(self):
        c = pr.ClashController(
            f"http://127.0.0.1:{self.port}", secret="test-secret", timeout=2
        )
        self.assertTrue(c.switch("飞鸟云", "美国04aws"))
        self.assertEqual(_FakeClashHandler.state["now"], "美国04aws")

    def test_controller_unreachable_fail_soft(self):
        c = pr.ClashController("http://127.0.0.1:1", secret="x", timeout=0.3)
        now, all_names = c.list_group_nodes("飞鸟云")
        self.assertEqual(now, "")
        self.assertEqual(all_names, [])

    def test_validate_rotation_config_uses_effective_cpa_proxy(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td), cpa_proxy="")
            pr.validate_rotation_config(cfg)
            with self.assertRaises(pr.EgressUnavailable):
                pr.validate_rotation_config(
                    self._cfg(Path(td), cpa_proxy="http://127.0.0.1:7891")
                )
        pr.validate_rotation_config({"proxy_rotation_enabled": False})

    def test_enabled_controller_failure_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(
                Path(td),
                proxy_rotation_controller_url="http://127.0.0.1:1",
                proxy_rotation_controller_timeout_sec=0.1,
            )
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with self.assertRaises(pr.EgressUnavailable):
                mgr.acquire()
            self.assertIsNone(mgr._process_lock_fh)
            self.assertIsNone(mgr._active)

    def test_rotation_disabled_is_only_static_lease_path(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td), proxy_rotation_enabled=False)
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("1.2.3.4", "US")):
                lease = mgr.acquire()
            self.assertTrue(lease.fixed)
            self.assertEqual(lease.meta["reason"], "rotation_disabled")
            mgr.release(lease, "soft_keep")

    def test_cooldown_blocks_same_ip(self):
        tmp = Path(self.id().replace(".", "_"))
        # use tempfile via pathlib under system tmp
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = self._cfg(tmp)
            mgr = pr.EgressLeaseManager(cfg, log=lambda m: None)

            with mock.patch.object(
                pr,
                "probe_egress",
                side_effect=[
                    ("1.1.1.1", "US"),
                    ("1.1.1.1", "US"),
                    ("1.1.1.1", "US"),
                    ("1.1.1.1", "US"),
                    ("2.2.2.2", "US"),
                    ("2.2.2.2", "US"),
                ],
            ):
                lease1 = mgr.acquire()
                self.assertEqual(lease1.egress_ip, "1.1.1.1")
                self.assertFalse(lease1.fixed)
                mgr.release(lease1, "healthy")

                # same IP should be cooling; next acquire should pick another node → 2.2.2.2
                lease2 = mgr.acquire()
                self.assertEqual(lease2.egress_ip, "2.2.2.2")
                mgr.release(lease2, "permission_denied")

                # denied cooldown longer — store has both IPs cooling
                rec = mgr.store.ip_record("1.1.1.1")
                self.assertGreater(float(rec.get("cooldown_until") or 0), time.time())
                rec2 = mgr.store.ip_record("2.2.2.2")
                self.assertGreater(float(rec2.get("cooldown_until") or 0), time.time())

    def test_permission_denied_uses_longer_cooldown(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td), proxy_rotation_cooldown_healthy_sec=10, proxy_rotation_cooldown_denied_sec=99)
            mgr = pr.EgressLeaseManager(cfg, log=lambda m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("9.9.9.9", "US")):
                lease = mgr.acquire()
                mgr.release(lease, "permission_denied")
            rec = mgr.store.ip_record("9.9.9.9")
            remain = float(rec["cooldown_until"]) - time.time()
            self.assertGreater(remain, 50)

    def test_bad_geo_skips_node(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda m: None)
            # First node returns SG, second US
            with mock.patch.object(
                pr,
                "probe_egress",
                side_effect=[
                    ("8.8.8.8", "SG"),
                    ("8.8.8.8", "SG"),
                    ("1.2.3.4", "US"),
                    ("1.2.3.4", "US"),
                ],
            ):
                lease = mgr.acquire()
            self.assertEqual(lease.country, "US")
            self.assertEqual(lease.egress_ip, "1.2.3.4")
            mgr.release(lease, "soft_keep")

    def test_unknown_country_is_rejected_when_us_required(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("8.8.8.8", "")):
                with self.assertRaisesRegex(pr.EgressUnavailable, "country unknown"):
                    mgr.acquire()
            self.assertIsNone(mgr._process_lock_fh)
            # Unknown country is fail-closed, but transient metadata loss must
            # not permanently quarantine the node as bad geography.
            self.assertTrue(
                all(
                    not float((mgr.store.node_record(node).get("bad_geo_until") or 0))
                    for node in mgr._filter_nodes(list(_FakeClashHandler.state["all"]))
                )
            )

    def test_all_known_egresses_cooling_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            nodes = mgr._filter_nodes(list(_FakeClashHandler.state["all"]))
            for index, node in enumerate(nodes, start=1):
                mgr.store.mark_outcome(
                    ip=f"10.1.0.{index}",
                    node=node,
                    outcome="healthy",
                    cooldown_sec=600,
                )
            with self.assertRaisesRegex(pr.EgressUnavailable, "cooling"):
                mgr.acquire()

    def test_max_switch_attempts_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td), proxy_rotation_max_switch_attempts=1)
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(mgr.controller, "switch", return_value=False):
                with self.assertRaises(pr.EgressUnavailable):
                    mgr.acquire()
            self.assertIsNone(mgr._process_lock_fh)

    def test_switch_must_be_confirmed_before_probe(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(
                Path(td),
                proxy_rotation_switch_confirm_timeout_sec=0.05,
                proxy_rotation_switch_confirm_interval_sec=0.01,
                proxy_rotation_max_switch_attempts=1,
            )
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            group_info = {
                "now": "wrong-node",
                "all": list(_FakeClashHandler.state["all"]),
            }
            with mock.patch.object(mgr.controller, "get_group", return_value=group_info), mock.patch.object(
                mgr.controller, "switch", return_value=True
            ), mock.patch.object(pr, "probe_egress") as probe:
                with self.assertRaisesRegex(pr.EgressUnavailable, "did not confirm"):
                    mgr.acquire()
            probe.assert_not_called()

    def test_lease_exclusivity_and_idempotent_release(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda m: None)
            seq = {"n": 0}

            def probe(*_a, **_k):
                seq["n"] += 1
                return (f"10.0.0.{((seq['n'] - 1) // 2) + 1}", "US")

            with mock.patch.object(pr, "probe_egress", side_effect=probe):
                lease1 = mgr.acquire()
                got = []

                def other():
                    # should block until release
                    t0 = time.time()
                    l2 = mgr.acquire()
                    got.append((time.time() - t0, l2.egress_ip))
                    mgr.release(l2, "soft_keep")

                th = threading.Thread(target=other)
                th.start()
                time.sleep(0.3)
                self.assertEqual(got, [])  # still blocked
                mgr.release(lease1, "healthy")
                # double release ok
                mgr.release(lease1, "healthy")
                th.join(timeout=5)
                self.assertEqual(len(got), 1)
                self.assertGreaterEqual(got[0][0], 0.25)

    def test_cross_manager_lock_respects_max_wait(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td), proxy_rotation_max_wait_sec=0.2)
            mgr1 = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            mgr2 = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("10.0.0.1", "US")):
                lease = mgr1.acquire()
                started = time.monotonic()
                with self.assertRaisesRegex(pr.EgressUnavailable, "max wait"):
                    mgr2.acquire()
                self.assertGreaterEqual(time.monotonic() - started, 0.15)
                mgr1.release(lease, "healthy")

    def test_state_reloads_after_cross_process_lock(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr1 = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            mgr2 = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("10.0.0.1", "US")):
                lease1 = mgr1.acquire()
                mgr1.release(lease1, "healthy")
            with mock.patch.object(
                pr,
                "probe_egress",
                side_effect=[
                    ("10.0.0.1", "US"),
                    ("10.0.0.1", "US"),
                    ("10.0.0.2", "US"),
                    ("10.0.0.2", "US"),
                ],
            ):
                lease2 = mgr2.acquire()
            self.assertEqual(lease2.egress_ip, "10.0.0.2")
            mgr2.release(lease2, "soft_keep")

    def test_egress_denied_breaker_and_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(
                Path(td),
                proxy_rotation_cooldown_egress_denied_sec=1800,
                proxy_rotation_egress_denied_breaker_threshold=2,
            )
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(
                pr,
                "probe_egress",
                side_effect=[
                    ("10.0.0.1", "US"),
                    ("10.0.0.1", "US"),
                    ("10.0.0.2", "US"),
                    ("10.0.0.2", "US"),
                ],
            ):
                lease1 = mgr.acquire()
                mgr.release(lease1, "egress_access_denied")
                self.assertFalse(mgr.should_stop_batch())
                lease2 = mgr.acquire()
                mgr.release(lease2, "egress_access_denied")
            self.assertTrue(mgr.batch_breaker_tripped())
            remain = float(mgr.store.ip_record("10.0.0.2")["cooldown_until"]) - time.time()
            self.assertGreater(remain, 1700)
            mgr.reset_batch_breaker()
            self.assertFalse(mgr.should_stop_batch())

    def test_ambiguous_forbidden_and_endpoint_do_not_trip_breaker(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(
                Path(td),
                proxy_rotation_cooldown_forbidden_unknown_sec=37,
                proxy_rotation_cooldown_soft_sec=23,
                proxy_rotation_egress_denied_breaker_threshold=1,
            )
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(
                pr,
                "probe_egress",
                side_effect=[
                    ("10.0.0.11", "US"),
                    ("10.0.0.11", "US"),
                    ("10.0.0.12", "US"),
                    ("10.0.0.12", "US"),
                ],
            ):
                lease1 = mgr.acquire()
                mgr.release(lease1, "generic_403")
                lease2 = mgr.acquire()
                mgr.release(lease2, "endpoint_inconsistent")
            self.assertFalse(mgr.should_stop_batch())
            unknown_remain = float(mgr.store.ip_record("10.0.0.11")["cooldown_until"]) - time.time()
            endpoint_remain = float(mgr.store.ip_record("10.0.0.12")["cooldown_until"]) - time.time()
            self.assertGreater(unknown_remain, 25)
            self.assertLess(unknown_remain, 45)
            self.assertGreater(endpoint_remain, 15)
            self.assertLess(endpoint_remain, 35)

    def test_history_hashes_ip_and_is_private(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            ip = "203.0.113.42"
            with mock.patch.object(pr, "probe_egress", return_value=(ip, "US")):
                lease = mgr.acquire()
                mgr.release(lease, "healthy")
            raw = mgr.history_path.read_text(encoding="utf-8")
            self.assertNotIn(ip, raw)
            self.assertIn(hashlib.sha256(ip.encode()).hexdigest()[:12], raw)
            self.assertEqual(os.stat(mgr.history_path).st_mode & 0o777, 0o600)

    def test_release_bookkeeping_failure_unlocks_then_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            mgr = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("10.0.0.9", "US")):
                lease = mgr.acquire()
            with mock.patch.object(mgr.store, "mark_outcome", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(pr.EgressUnavailable, "bookkeeping failed"):
                    mgr.release(lease, "egress_access_denied")
            self.assertIsNone(mgr._active)
            self.assertIsNone(mgr._process_lock_fh)

            # The lifecycle lock must not remain wedged after the fail-closed error.
            replacement = pr.EgressLeaseManager(cfg, log=lambda _m: None)
            with mock.patch.object(pr, "probe_egress", return_value=("10.0.0.10", "US")):
                next_lease = replacement.acquire()
                replacement.release(next_lease, "healthy")

    def test_apply_rotation_concurrency(self):
        t, m, changed = pr.apply_rotation_concurrency(
            {"proxy_rotation_enabled": True}, threads=3, mint_workers=2
        )
        self.assertEqual((t, m, changed), (1, 0, True))
        t2, m2, ch2 = pr.apply_rotation_concurrency(
            {"proxy_rotation_enabled": False}, threads=3, mint_workers=2
        )
        self.assertEqual((t2, m2, ch2), (3, 2, False))

    def test_map_registration_outcome(self):
        self.assertEqual(pr.map_registration_outcome("rejected"), "permission_denied")
        self.assertEqual(
            pr.map_registration_outcome(
                "accepted", {"health": {"classification": "healthy"}}
            ),
            "healthy",
        )
        self.assertEqual(
            pr.map_registration_outcome(
                "accepted", {"health": {"classification": "probe_error"}}
            ),
            "soft_keep",
        )
        self.assertEqual(pr.map_registration_outcome("activation_failed"), "activation_failed")
        self.assertEqual(
            pr.map_registration_outcome(
                "permission_denied",
                {"health": {"classification": "egress_access_denied"}, "rejected": True},
            ),
            "egress_access_denied",
        )
        self.assertEqual(
            pr.map_registration_outcome(
                "accepted", {"health": {"classification": "forbidden_unknown"}}
            ),
            "forbidden_unknown",
        )
        self.assertEqual(
            pr.map_registration_outcome(
                "accepted", {"health": {"classification": "generic_403"}}
            ),
            "forbidden_unknown",
        )
        self.assertEqual(
            pr.map_registration_outcome(
                "accepted", {"health": {"classification": "endpoint_inconsistent"}}
            ),
            "endpoint_inconsistent",
        )

    def test_get_manager_singleton(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(Path(td))
            a = pr.get_manager(cfg)
            b = pr.get_manager(cfg)
            self.assertIs(a, b)
            changed = pr.get_manager(dict(cfg, proxy_rotation_require_us=False))
            self.assertIsNot(a, changed)


if __name__ == "__main__":
    unittest.main()
