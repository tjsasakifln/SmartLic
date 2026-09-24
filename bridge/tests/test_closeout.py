"""Closeout proofs: drive shipped generate/policy/serve/apply/preflight/observe/monitor."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from bridge.apply import (
    AUTHORIZED_ENV_NAMES,
    CLOSEOUT_CAMPAIGN,
    EXACT_COMMAND,
    NOMINAL_BLOCKED,
    SINGLE_HUMAN_ACTION,
    SMOKE_READY_LOCATION,
    SMOKE_READY_PATH,
    VERDICT_CODE_COMPLETE,
    VERDICT_OBSERVATION_STARTED,
    build_residual,
    operator_one_shot_text,
    run_apply,
)
from bridge.generate import load_and_compile
from bridge.monitor import collect_daily_snapshot
from bridge.observe import evaluate_signals, observation_exit_fields
from bridge.pins import (
    FORBIDDEN_GENERIC_TARGETS,
    MIN_ALLOWED_TRAFFIC_COUNT,
    OBSERVATION_WINDOW_DAYS,
    PINNED_CANONICAL_HOST,
    PINNED_CONFIG_SHA256,
    PINNED_HOLD_COUNT,
    PINNED_REDIRECT_COUNT,
    PINNED_SHA256,
    TARGET_HOSTNAME,
)
from bridge.policy import resolve
from bridge.preflight import (
    LIVE_HOSTS,
    ProductionProbe,
    TlsObservation,
    start_observation_window,
)

ROOT = Path(__file__).resolve().parents[2]
FIXED = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)


def _offline_head(host: str, path: str) -> dict:
    return {
        "host": host,
        "path": path,
        "status": 0,
        "has_location": False,
        "config_hash": "",
        "error": "gaierror",
        "hops": 0,
        "loop": False,
    }


def _offline_tls(host: str) -> TlsObservation:
    return TlsObservation(hostname=host, ok=False, error="gaierror")


def _observe_empty(hostname: str):
    from bridge.preflight import DnsObservation

    return DnsObservation(hostname=hostname, addresses=())


class PinnedExecuteSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiled = load_and_compile()

    def test_eleven_ready_301s_are_confenge_one_hop(self) -> None:
        self.assertEqual(len(self.compiled.redirects), PINNED_REDIRECT_COUNT)
        self.assertEqual(len(self.compiled.holds), PINNED_HOLD_COUNT)
        self.assertEqual(self.compiled.default_status, 410)
        self.assertEqual(self.compiled.config_sha256, PINNED_CONFIG_SHA256)
        self.assertEqual(self.compiled.manifesto_sha256, PINNED_SHA256)
        seen = set()
        for rule in self.compiled.redirects:
            decision = resolve(self.compiled, rule.path, "", "smartlic.tech")
            self.assertEqual(decision.status, 301, rule.path)
            self.assertEqual(decision.location, rule.target_url, rule.path)
            self.assertEqual(decision.hops, 1, rule.path)
            host = (urlsplit(decision.location or "").hostname or "")
            self.assertEqual(host, TARGET_HOSTNAME, rule.path)
            self.assertTrue((decision.location or "").startswith(PINNED_CANONICAL_HOST + "/"))
            self.assertNotIn(decision.location, FORBIDDEN_GENERIC_TARGETS)
            path = urlsplit(decision.location or "").path or "/"
            self.assertNotIn(path, {"/", "/consultoria-b2g", "/consultoria-b2g/"})
            self.assertNotIn("smartlic.tech", (decision.location or "").lower())
            self.assertNotIn(rule.path, seen)
            seen.add(rule.path)
        self.assertEqual(len(seen), PINNED_REDIRECT_COUNT)
        smoke = resolve(self.compiled, SMOKE_READY_PATH, "", "smartlic.tech")
        self.assertEqual(smoke.status, 301)
        self.assertEqual(smoke.location, SMOKE_READY_LOCATION)

    def test_hold_retire_home_login_api_are_410_no_location(self) -> None:
        cases = [
            *self.compiled.holds[:5],
            "/",
            "/login",
            "/signup",
            "/pricing",
            "/webhooks",
            "/v1",
            "/not-mapped-closeout",
            "/api/health",
        ]
        for path in cases:
            decision = resolve(self.compiled, path, "", "smartlic.tech")
            self.assertEqual(decision.status, 410, path)
            self.assertIsNone(decision.location, path)
            self.assertEqual(decision.hops, 0, path)


class ObservationWindowCloseoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiled = load_and_compile()
        cls.ready = cls.compiled.redirects[0]

    def test_days_elapsed_and_min_traffic_fields(self) -> None:
        summary = {
            "config_sha256": PINNED_CONFIG_SHA256,
            "counts": {"301": 0, "404": 0, "errors": 0, "5xx": 0, "chain_gt1": 0, "loop": 0},
            "target_health": {"status": "OK"},
        }
        unobserved = evaluate_signals(summary, now=FIXED)
        self.assertFalse(unobserved["window_started"])
        self.assertEqual(unobserved["observation_days_elapsed"], 0)
        self.assertEqual(unobserved["min_allowed_traffic_count"], MIN_ALLOWED_TRAFFIC_COUNT)
        self.assertEqual(unobserved["traffic_count"], 0)
        self.assertFalse(unobserved["chain"])
        self.assertFalse(unobserved["loop"])
        self.assertEqual(unobserved["target"], PINNED_CANONICAL_HOST)
        self.assertEqual(unobserved["removal"], "HOLD_WINDOW_NOT_STARTED")

        started = evaluate_signals(
            summary,
            production_first_301={
                "status": "OBSERVED",
                "config_sha256": PINNED_CONFIG_SHA256,
                "observation_started_at": "2026-08-01T12:00:00Z",
                "http_status": 301,
            },
            now=FIXED,
        )
        self.assertTrue(started["window_started"])
        self.assertEqual(started["observation_days_elapsed"], 19)
        self.assertFalse(started["window_elapsed"])
        self.assertEqual(started["traffic_count"], MIN_ALLOWED_TRAFFIC_COUNT)
        self.assertEqual(started["removal"], "WAIT_WINDOW")

        elapsed = evaluate_signals(
            {**summary, "counts": {"301": 4, "404": 0, "errors": 0, "5xx": 0, "chain_gt1": 0, "loop": 0}},
            production_first_301={
                "status": "OBSERVED",
                "config_sha256": PINNED_CONFIG_SHA256,
                "observation_started_at": "2026-07-01T12:00:00Z",
                "http_status": 301,
            },
            now=FIXED,
        )
        self.assertTrue(elapsed["window_elapsed"])
        self.assertGreaterEqual(elapsed["observation_days_elapsed"], OBSERVATION_WINDOW_DAYS)
        self.assertEqual(elapsed["removal"], "READY_FOR_REVIEW")

        looped = evaluate_signals(
            {**summary, "counts": {"301": 1, "loop": 1, "chain_gt1": 0, "404": 0, "errors": 0, "5xx": 0}},
            production_first_301={
                "status": "OBSERVED",
                "config_sha256": PINNED_CONFIG_SHA256,
                "observation_started_at": "2026-07-01T12:00:00Z",
            },
            now=FIXED,
        )
        self.assertTrue(looped["loop"])
        self.assertTrue(looped["residual_priority"])
        self.assertEqual(looped["removal"], "HOLD_RESIDUAL")

        exit_fields = observation_exit_fields(
            started,
            production_first_301={
                "status": "OBSERVED",
                "config_sha256": PINNED_CONFIG_SHA256,
                "observation_started_at": "2026-08-01T12:00:00Z",
                "http_status": 301,
            },
            removal_trigger=self.compiled.removal_trigger,
            config_sha256=PINNED_CONFIG_SHA256,
        )
        self.assertEqual(exit_fields["config_sha256"], PINNED_CONFIG_SHA256)
        self.assertEqual(exit_fields["first_production_301_timestamp"], "2026-08-01T12:00:00Z")
        self.assertEqual(exit_fields["http_status"], 301)
        self.assertFalse(exit_fields["chain"])
        self.assertFalse(exit_fields["loop"])
        self.assertEqual(exit_fields["target"], PINNED_CANONICAL_HOST)
        self.assertEqual(exit_fields["min_allowed_traffic_count"], 1)
        self.assertEqual(exit_fields["observation_days_elapsed"], 19)
        self.assertIn("28-day", exit_fields["removal_trigger"])

    def test_loopback_fixture_mock_do_not_start_window(self) -> None:
        for source in ("loopback", "fixture", "mock"):
            probe = ProductionProbe(
                host="127.0.0.1" if source == "loopback" else "smartlic.tech",
                path=self.ready.path,
                status=301,
                location=self.ready.target_url,
                config_hash=PINNED_CONFIG_SHA256,
                source=source,
                captured_at="2026-08-20T12:00:00Z",
            )
            payload = start_observation_window(probe, self.compiled)
            self.assertIsNone(payload["observation_started_at"], source)
            self.assertNotEqual(payload["first_production_301"], "OBSERVED", source)


class MonitorIdempotencyTests(unittest.TestCase):
    def test_snapshot_does_not_start_window_and_is_stable(self) -> None:
        observation = {
            "status": "UNOBSERVED",
            "first_production_301": "UNOBSERVED",
            "observation_started_at": None,
            "config_sha256": PINNED_CONFIG_SHA256,
        }
        clock = lambda: "2026-08-20T12:00:00Z"
        first = collect_daily_snapshot(
            observation=observation,
            head_fn=_offline_head,
            tls_fn=_offline_tls,
            clock=clock,
            now=FIXED,
        )
        second = collect_daily_snapshot(
            observation=observation,
            head_fn=_offline_head,
            tls_fn=_offline_tls,
            clock=clock,
            now=FIXED,
        )
        self.assertEqual(first, second)
        self.assertFalse(first["window_start_invoked"])
        self.assertIsNone(first["observation_started_at"])
        self.assertEqual(first["first_production_301"], "UNOBSERVED")
        self.assertEqual(first["signals"]["removal"], "HOLD_WINDOW_NOT_STARTED")
        self.assertEqual(first["exit"]["observation_days_elapsed"], 0)
        self.assertEqual(first["exit"]["min_allowed_traffic_count"], MIN_ALLOWED_TRAFFIC_COUNT)
        self.assertFalse(first["exit"]["chain"])
        self.assertFalse(first["exit"]["loop"])
        self.assertEqual(first["config_sha256"], PINNED_CONFIG_SHA256)
        self.assertEqual(set(first["tls"]), set(LIVE_HOSTS))
        text = Path(__file__).resolve().parents[1].joinpath("monitor.py").read_text(encoding="utf-8")
        self.assertNotIn("start_observation_window(", text)

    def test_consumed_production_observation_does_not_rewrite_start(self) -> None:
        observation = {
            "status": "OBSERVED",
            "first_production_301": "OBSERVED",
            "observation_started_at": "2026-08-01T12:00:00Z",
            "captured_at": "2026-08-01T12:00:00Z",
            "config_sha256": PINNED_CONFIG_SHA256,
            "http_status": 301,
        }
        clock = lambda: "2026-08-20T12:00:00Z"
        first = collect_daily_snapshot(
            observation=observation,
            head_fn=_offline_head,
            tls_fn=_offline_tls,
            clock=clock,
            now=FIXED,
        )
        second = collect_daily_snapshot(
            observation=observation,
            head_fn=_offline_head,
            tls_fn=_offline_tls,
            clock=clock,
            now=FIXED,
        )
        self.assertEqual(first, second)
        self.assertFalse(first["window_start_invoked"])
        self.assertEqual(first["observation_started_at"], "2026-08-01T12:00:00Z")
        self.assertEqual(first["exit"]["observation_days_elapsed"], 19)
        # Offline gaierror counts as residual until public 301s exist.
        self.assertEqual(first["signals"]["removal"], "HOLD_RESIDUAL")

        compiled = load_and_compile()
        ready_paths = {rule.path for rule in compiled.redirects}

        def healthy_head(host: str, path: str) -> dict:
            if path in ready_paths:
                return {
                    "host": host,
                    "path": path,
                    "status": 301,
                    "has_location": True,
                    "config_hash": PINNED_CONFIG_SHA256,
                    "hops": 1,
                    "loop": False,
                }
            return {
                "host": host,
                "path": path,
                "status": 410,
                "has_location": False,
                "config_hash": PINNED_CONFIG_SHA256,
                "hops": 0,
                "loop": False,
            }

        healthy = collect_daily_snapshot(
            observation=observation,
            head_fn=healthy_head,
            tls_fn=lambda host: TlsObservation(hostname=host, ok=True),
            clock=clock,
            now=FIXED,
        )
        self.assertEqual(healthy["signals"]["removal"], "WAIT_WINDOW")
        self.assertGreaterEqual(healthy["ready_301"], PINNED_REDIRECT_COUNT)
        self.assertFalse(healthy["window_start_invoked"])


class ResidualAndOperatorTests(unittest.TestCase):
    def test_run_apply_emits_residual_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = run_apply(
                environ={},
                env_file=Path(tmp) / "missing",
                observe_dns_fn=_observe_empty,
                observe_tls_fn=_offline_tls,
            )
        self.assertEqual(payload["status"], NOMINAL_BLOCKED)
        self.assertFalse(payload["applied"])
        residual = payload["residual"]
        self.assertEqual(residual["verdict"], VERDICT_CODE_COMPLETE)
        self.assertEqual(residual["campaign"], CLOSEOUT_CAMPAIGN)
        self.assertEqual(residual["exact_command"], EXACT_COMMAND)
        self.assertEqual(residual["min_vars"], list(AUTHORIZED_ENV_NAMES))
        self.assertEqual(set(residual["missing"]), set(AUTHORIZED_ENV_NAMES))
        self.assertIn("python3 -m bridge.generate --rollback", residual["rollback"][0])
        self.assertTrue(residual["post_apply_smokes"])
        self.assertEqual(residual["observation"]["min_allowed_traffic_count"], 1)
        self.assertIsNone(residual["observation"]["first_production_301_timestamp"])
        blob = json.dumps(payload)
        self.assertNotIn("Bearer ", blob)
        for name in AUTHORIZED_ENV_NAMES:
            self.assertNotRegex(blob, rf"{name}=[A-Za-z0-9_\-]{{8,}}")
        rebuilt = build_residual(payload)
        self.assertEqual(rebuilt["verdict"], VERDICT_CODE_COMPLETE)
        self.assertNotEqual(rebuilt["verdict"], VERDICT_OBSERVATION_STARTED)

    def test_operator_one_shot_is_the_single_sequence(self) -> None:
        text = operator_one_shot_text()
        self.assertIn(EXACT_COMMAND, text)
        self.assertIn("python3 -m bridge.preflight", text)
        self.assertIn("python3 -m bridge.apply --attach-live-transport", text)
        for name in AUTHORIZED_ENV_NAMES:
            self.assertIn(name, text)
        self.assertIn(SINGLE_HUMAN_ACTION, text)
        self.assertIn("python3 -m bridge.generate --rollback", text)
        self.assertIn("69.46.46.88", text)
        self.assertIn("159.195.18.88", text)
        self.assertIn("do_not_invent_values=true", text)
        self.assertIn(SMOKE_READY_PATH, text)
        self.assertIn(PINNED_CONFIG_SHA256, text)
        self.assertNotIn("sk_live_", text)
        committed = ROOT / "docs/campaigns" / CLOSEOUT_CAMPAIGN / "OPERATOR_ONE_SHOT.txt"
        self.assertEqual(committed.read_text(encoding="utf-8"), text)
        residual_path = ROOT / "docs/campaigns" / CLOSEOUT_CAMPAIGN / "residual.json"
        on_disk = json.loads(residual_path.read_text(encoding="utf-8"))
        self.assertEqual(on_disk["verdict"], VERDICT_CODE_COMPLETE)
        self.assertEqual(on_disk["exact_command"], EXACT_COMMAND)
        self.assertEqual(on_disk["min_vars"], list(AUTHORIZED_ENV_NAMES))
        self.assertFalse(on_disk["applied"])
        blob = residual_path.read_text(encoding="utf-8")
        self.assertNotIn("Bearer ", blob)
        for forbidden in ("sk_live_", "ghp_", "cf_"):
            # residual names the env vars; it must not contain values.
            self.assertNotRegex(blob, rf"{forbidden}[A-Za-z0-9_\-]{{8,}}")


if __name__ == "__main__":
    unittest.main()
