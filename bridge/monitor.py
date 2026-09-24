#!/usr/bin/env python3
"""Bounded daily snapshot for the #2115 window. No query PII.

Does not start observation_started_at. Loopback/fixture probes are ignored
for window start. Not an analytics product.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bridge.generate import load_and_compile
from bridge.observe import assert_no_pii, evaluate_signals, observation_exit_fields
from bridge.pins import PINNED_CONFIG_SHA256, PINNED_SHA256
from bridge.preflight import LIVE_HOSTS, TlsObservation, observe_tls

HOLD_SAMPLE = "/blog/como-consultar-contratos-publicos-pncp"
GONE_PATHS = ("/", "/login", "/signup", "/pricing", "/webhooks", "/v1")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _head(host: str, path: str) -> dict[str, Any]:
    import http.client

    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=15, context=ctx)
    try:
        conn.request("HEAD", path, headers={"Host": host, "User-Agent": "SmartLic-2115-monitor/1.0"})
        resp = conn.getresponse()
        resp.read()
        return {
            "host": host,
            "path": path,
            "status": int(resp.status),
            "has_location": resp.getheader("Location") is not None,
            "config_hash": resp.getheader("X-Bridge-Config-Hash") or "",
        }
    except Exception as exc:  # noqa: BLE001 — monitor must surface the class only
        return {
            "host": host,
            "path": path,
            "status": 0,
            "has_location": False,
            "config_hash": "",
            "error": type(exc).__name__,
        }
    finally:
        conn.close()


def collect_daily_snapshot(
    *,
    observation: dict[str, Any] | None = None,
    head_fn=None,
    tls_fn=None,
    clock=None,
    now=None,
) -> dict[str, Any]:
    """Bounded snapshot. Does not start the 28-day observation window."""
    probe = head_fn or _head
    tls_probe = tls_fn or observe_tls
    compiled = load_and_compile()
    ready_hits = []
    gone_hits = []
    for host in sorted(LIVE_HOSTS):
        for rule in compiled.redirects:
            ready_hits.append(probe(host, rule.path))
        for path in GONE_PATHS + (HOLD_SAMPLE, "/not-mapped-2115-monitor"):
            gone_hits.append(probe(host, path))
    tls: dict[str, dict[str, bool]] = {}
    for host in sorted(LIVE_HOSTS):
        seen = tls_probe(host)
        ok = bool(seen.ok) if isinstance(seen, TlsObservation) else bool(seen)
        tls[host] = {"ok": ok}
    hash_ok = all(
        (row.get("config_hash") == PINNED_CONFIG_SHA256) or row.get("status") in {0, 404}
        for row in ready_hits
    )
    chain_hits = sum(1 for row in ready_hits if int(row.get("hops") or 0) > 1)
    loop_hits = sum(1 for row in ready_hits if row.get("loop"))
    ready_301 = sum(1 for row in ready_hits if row.get("status") == 301)
    signals = evaluate_signals(
        {
            "config_sha256": compiled.config_sha256,
            "counts": {
                "301": ready_301,
                "404": sum(1 for row in ready_hits + gone_hits if row.get("status") == 404),
                "errors": sum(1 for row in ready_hits + gone_hits if row.get("error")),
                "5xx": sum(1 for row in ready_hits + gone_hits if int(row.get("status") or 0) >= 500),
                "chain_gt1": chain_hits,
                "loop": loop_hits,
            },
            "target_health": {"status": "UNOBSERVED"},
        },
        production_first_301=observation,
        now=now,
    )
    exit_fields = observation_exit_fields(
        signals,
        production_first_301=observation,
        removal_trigger=compiled.removal_trigger,
        config_sha256=compiled.config_sha256,
    )
    payload = {
        "ts": (clock or utc_now)() if callable(clock) else utc_now(),
        "manifesto_sha256": PINNED_SHA256,
        "config_sha256": PINNED_CONFIG_SHA256,
        "ready_checked": len(ready_hits),
        "gone_checked": len(gone_hits),
        "ready_301": ready_301,
        "gone_410": sum(1 for row in gone_hits if row.get("status") == 410),
        "tls": tls,
        "hash_header_pin_ok": hash_ok,
        "signals": signals,
        "exit": exit_fields,
        "observation_started_at": (observation or {}).get("observation_started_at"),
        "first_production_301": (observation or {}).get("first_production_301") or "UNOBSERVED",
        "window_start_invoked": False,
    }
    assert_no_pii(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Daily #2115 snapshot. Does not start the window.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--observation", type=Path, default=None)
    args = parser.parse_args(argv)
    observation = None
    if args.observation is not None and args.observation.is_file():
        observation = json.loads(args.observation.read_text(encoding="utf-8"))
    payload = collect_daily_snapshot(observation=observation)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert_no_pii(body)
    args.out.write_text(body, encoding="utf-8")
    print(
        "MONITOR_OK "
        f"ready_301={payload['ready_301']}/{payload['ready_checked']} "
        f"gone_410={payload['gone_410']}/{payload['gone_checked']} "
        f"window={payload['signals']['removal']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
