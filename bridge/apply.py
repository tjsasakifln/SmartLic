#!/usr/bin/env python3
"""Fail-closed live apply for the hash-pinned #2115 redirect bridge.

Authorized credential routes only:
  - process environment
  - /etc/smartlic-bridge/env

Never prints secret values. Never mutates api.smartlic.tech, app,
NS, TXT, or MX. Never starts a SmartLic product runtime.
Never writes smartlic.tech records into the confenge.com.br zone.
Loopback/fixture/mock probes cannot start the 28-day window.
Empty apex/www DNS is the cutover start state, not a RETIRE of the
11-row map. Isolated IPv4 + smartlic.tech CF creds are still required.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

from bridge.errors import ManifestError
from bridge.generate import load_and_compile
from bridge.observe import evaluate_signals, observation_exit_fields
from bridge.pins import (
    MIN_ALLOWED_TRAFFIC_COUNT,
    OBSERVATION_WINDOW_DAYS,
    PINNED_CANONICAL_HOST,
    PINNED_COMMIT,
    PINNED_CONFIG_SHA256,
    PINNED_SHA256,
)
from bridge.preflight import (
    BASELINE_APEX_A,
    DnsObservation,
    LIVE_HOSTS,
    ProductionProbe,
    TlsObservation,
    env_value,
    is_public_ipv4,
    observe_dns,
    observe_tls,
    redact_secrets,
    start_observation_window,
)

AUTHORIZED_ENV_NAMES = (
    "BRIDGE_PUBLIC_IPV4",
    "SMARTLIC_ACME_EMAIL",
    "CF_API_TOKEN",
    "CF_ZONE_ID",
)
AUTHORIZED_ENV_FILE = Path("/etc/smartlic-bridge/env")
ALLOWED_DNS_NAMES = frozenset({"smartlic.tech", "www.smartlic.tech"})
CANONICAL_PUBLIC_ZONE = "confenge.com.br"
FORBIDDEN_CF_ZONE_NAMES = frozenset(
    {
        "confenge.com.br",
        "www.confenge.com.br",
        "api.confenge.com.br",
    }
)
FORBIDDEN_DNS_NAMES = frozenset(
    {
        "api.smartlic.tech",
        "app.smartlic.tech",
    }
)
# extra-cli / warmbly production — already terminates api.confenge.com.br on :80/:443.
FORBIDDEN_SHARED_IPV4 = frozenset({"159.195.18.88"})
FORBIDDEN_DNS_TYPES = frozenset({"NS", "TXT", "MX", "AAAA"})
PRODUCT_RUNTIME_TOKENS = (
    "fastapi",
    "uvicorn",
    "gunicorn",
    "next.js",
    "next start",
    "npm run start",
    "redis",
    "supabase",
    "railway",
    "arq ",
    "celery",
    "postgres",
    "stripe",
    "backend.main",
    "frontend/app",
)
CF_API = "https://api.cloudflare.com/client/v4"
SINGLE_HUMAN_ACTION = (
    "Write /etc/smartlic-bridge/env (mode 0640) on an isolated public IPv4 "
    "host that is not 159.195.18.88 (extra-cli/warmbly prod) with "
    "BRIDGE_PUBLIC_IPV4=<that isolated IPv4> and SMARTLIC_ACME_EMAIL="
    "<ops contact>, export CF_API_TOKEN and CF_ZONE_ID for zone "
    "smartlic.tech (never confenge.com.br) in the apply shell, then "
    "re-run `python3 -m bridge.apply`."
)
CLOSEOUT_CAMPAIGN = "CONFENGE-SMARTLIC-EQUITY-BRIDGE-CLOSEOUT-01"
VERDICT_CODE_COMPLETE = "BRIDGE_CODE_COMPLETE_EXTERNAL_ACTION_REQUIRED"
VERDICT_OBSERVATION_STARTED = "BRIDGE_PRODUCTION_OBSERVATION_STARTED"
VERDICT_DEFECT = "BRIDGE_DEFECT_FOUND"
NOMINAL_BLOCKED = "BLOCKED_SINGLE_EXTERNAL_ACTION"
EXACT_COMMAND = "python3 -m bridge.preflight && python3 -m bridge.apply --attach-live-transport"
SMOKE_READY_PATH = "/glossario/reajuste"
SMOKE_READY_LOCATION = "https://confenge.com.br/reequilibrio-obras-publicas/"
ROLLBACK_MAP = "python3 -m bridge.generate --rollback"
ROLLBACK_DNS = (
    "DNS baseline (does not start SmartLic): apex A 69.46.46.88 TTL 60; "
    "delete www A; recreate www CNAME app.smartlic.tech. TTL 300 proxied=false"
)
EXPECTED_WITHOUT_SECRETS = (
    "PREFLIGHT_BLOCKED field=BRIDGE_PUBLIC_IPV4 (or the first missing "
    "authorized name); APPLY_BLOCKED_SINGLE_EXTERNAL_ACTION applied=false; "
    "no Cloudflare write; observation_started_at=null"
)
EXPECTED_WITH_SECRETS = (
    "PREFLIGHT_OK then APPLY_APPLIED or APPLY_LIVE_CUTOVER_PROVEN_OBSERVATION_STARTED "
    "on isolated IPv4 + smartlic.tech CF zone; first live 301 of this hash starts "
    f"the {OBSERVATION_WINDOW_DAYS}-day window"
)

Transport = Callable[[str, str, Mapping[str, str], bytes | None], dict[str, Any]]


@dataclass(frozen=True)
class DnsMutation:
    op: str
    type: str
    name: str
    content: str | None = None
    ttl: int | None = None
    proxied: bool = False


def load_authorized_env(
    environ: Mapping[str, str] | None = None,
    env_file: Path | None = AUTHORIZED_ENV_FILE,
) -> dict[str, str]:
    """Load only the four authorized names. Values are never logged."""
    values: dict[str, str] = {}
    if env_file is not None and env_file.is_file():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, raw = stripped.partition("=")
                key = key.strip()
                if key not in AUTHORIZED_ENV_NAMES:
                    continue
                value = raw.strip().strip('"').strip("'")
                if value:
                    values[key] = value
        except OSError:
            pass
    source = os.environ if environ is None else environ
    for name in AUTHORIZED_ENV_NAMES:
        found = env_value(name, source)
        if found:
            values[name] = found
    return values


def credential_presence(values: Mapping[str, str]) -> dict[str, bool]:
    return {name: bool(values.get(name, "").strip()) for name in AUTHORIZED_ENV_NAMES}


def missing_credentials(values: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(name for name in AUTHORIZED_ENV_NAMES if not values.get(name, "").strip())


def post_apply_smokes(*, config_sha256: str = PINNED_CONFIG_SHA256) -> list[dict[str, str]]:
    return [
        {
            "command": f"curl -sI https://smartlic.tech{SMOKE_READY_PATH}",
            "expect": (
                f"HTTP 301 Location: {SMOKE_READY_LOCATION} "
                f"X-Bridge-Config-Hash: {config_sha256}"
            ),
        },
        {
            "command": "curl -sI https://smartlic.tech/login",
            "expect": "HTTP 410 and no Location",
        },
        {
            "command": "curl -sI https://smartlic.tech/",
            "expect": "HTTP 410 and no Location (no blanket home redirect)",
        },
        {
            "command": "curl -sI https://www.smartlic.tech" + SMOKE_READY_PATH,
            "expect": f"HTTP 301 Location: {SMOKE_READY_LOCATION} (same hash)",
        },
        {
            "command": "python3 -m bridge.monitor --out window-daily.json",
            "expect": "MONITOR_OK; does not start observation_started_at",
        },
    ]


def closeout_verdict(apply_payload: Mapping[str, Any]) -> str:
    observation = apply_payload.get("observation") or {}
    started = observation.get("observation_started_at")
    first = observation.get("first_production_301")
    if first == "OBSERVED" and started:
        return VERDICT_OBSERVATION_STARTED
    return VERDICT_CODE_COMPLETE


def build_residual(
    apply_payload: Mapping[str, Any],
    *,
    compiled=None,
) -> dict[str, Any]:
    """Machine-readable residual. Never includes secret values."""
    from bridge.generate import load_and_compile as _load

    compiled = compiled or _load()
    observation = apply_payload.get("observation") or {}
    missing = list(apply_payload.get("missing") or missing_credentials({}))
    signals = evaluate_signals(
        {
            "config_sha256": compiled.config_sha256,
            "counts": {"301": 0, "404": 0, "errors": 0, "5xx": 0, "chain_gt1": 0, "loop": 0},
            "target_health": {"status": "UNOBSERVED"},
        },
        production_first_301=observation if observation.get("first_production_301") == "OBSERVED" else None,
    )
    exit_fields = observation_exit_fields(
        signals,
        production_first_301=observation,
        removal_trigger=compiled.removal_trigger,
        config_sha256=compiled.config_sha256,
    )
    verdict = closeout_verdict(apply_payload)
    residual = {
        "campaign": CLOSEOUT_CAMPAIGN,
        "verdict": verdict,
        "status": apply_payload.get("status") or NOMINAL_BLOCKED,
        "nominal_error": NOMINAL_BLOCKED,
        "applied": bool(apply_payload.get("applied")),
        "dns_mutated": bool(apply_payload.get("applied")),
        "tls_mutated": False,
        "observation_started": verdict == VERDICT_OBSERVATION_STARTED,
        "missing": missing,
        "min_vars": list(AUTHORIZED_ENV_NAMES),
        "exact_command": EXACT_COMMAND,
        "single_human_action": SINGLE_HUMAN_ACTION,
        "expected_without_secrets": EXPECTED_WITHOUT_SECRETS,
        "expected_with_secrets": EXPECTED_WITH_SECRETS,
        "rollback": [ROLLBACK_MAP, ROLLBACK_DNS],
        "post_apply_smokes": post_apply_smokes(config_sha256=compiled.config_sha256),
        "manifesto_sha256": compiled.manifesto_sha256,
        "config_sha256": compiled.config_sha256,
        "pinned_commit": PINNED_COMMIT,
        "canonical_host": PINNED_CANONICAL_HOST,
        "redirects": 11,
        "default_status": 410,
        "observation_window_days": OBSERVATION_WINDOW_DAYS,
        "min_allowed_traffic_count": MIN_ALLOWED_TRAFFIC_COUNT,
        "observation": exit_fields,
        "forbidden": [
            "do not invent BRIDGE_PUBLIC_IPV4 / SMARTLIC_ACME_EMAIL / CF_API_TOKEN / CF_ZONE_ID",
            "do not write confenge.com.br Cloudflare zone",
            "do not use extra-cli/warmbly 159.195.18.88",
            "do not revive api.smartlic.tech as an API",
            "do not restore a SmartLic application runtime or billing",
        ],
    }
    return json.loads(redact_secrets(json.dumps(residual, ensure_ascii=False)))


def operator_one_shot_text(*, config_sha256: str = PINNED_CONFIG_SHA256) -> str:
    smokes = "\n".join(
        f"  {row['command']}\n    expect: {row['expect']}"
        for row in post_apply_smokes(config_sha256=config_sha256)
    )
    return f"""OPERATOR_ONE_SHOT {CLOSEOUT_CAMPAIGN}
verdict={VERDICT_CODE_COMPLETE}
do_not_edit_code=true
do_not_invent_values=true

MIN_VARS (never commit; zone smartlic.tech only, never confenge.com.br)
  BRIDGE_PUBLIC_IPV4
  SMARTLIC_ACME_EMAIL
  CF_API_TOKEN
  CF_ZONE_ID

1. UNIQUE PREFLIGHT (read-only; no DNS/TLS write)
  python3 -m bridge.preflight
  nominal_error: PREFLIGHT_BLOCKED field=<first missing name>
  expected_without_secrets: exit 2; dns_mutated=false; tls_mutated=false

2. EXACT COMMAND (on isolated public IPv4 host, not 159.195.18.88)
  {SINGLE_HUMAN_ACTION}
  {EXACT_COMMAND}
  expected_without_secrets: {EXPECTED_WITHOUT_SECRETS}
  expected_with_secrets: {EXPECTED_WITH_SECRETS}

3. POST-APPLY SMOKES
{smokes}

4. ROLLBACK
  {ROLLBACK_MAP}
    expect: every previously-ready path returns 410 and no Location
  {ROLLBACK_DNS}

WINDOW
  starts only after a real production 301 of config {config_sha256}
  loopback/fixture/mock/monitor snapshot do not start it
  {OBSERVATION_WINDOW_DAYS} days; min traffic count {MIN_ALLOWED_TRAFFIC_COUNT}
"""


def assert_cf_zone_allowed(zone_name: str | None) -> None:
    name = (zone_name or "").strip().lower().rstrip(".")
    if not name:
        raise ManifestError("BLOCKED_SAFETY_CONFLICT: CF zone name is empty")
    if name in FORBIDDEN_CF_ZONE_NAMES:
        raise ManifestError(
            "BLOCKED_SAFETY_CONFLICT: refuse to mutate canonical public zone "
            f"{name}"
        )
    if name != "smartlic.tech":
        raise ManifestError(
            "BLOCKED_SAFETY_CONFLICT: CF_ZONE_ID is not smartlic.tech"
        )


def _zone_url(zone_id: str) -> str:
    return f"{CF_API}/zones/{zone_id}"


def dns_plan(target_ip: str) -> tuple[DnsMutation, ...]:
    if not is_public_ipv4(target_ip):
        raise ManifestError("dns_plan refused: target is not a public IPv4")
    if target_ip in FORBIDDEN_SHARED_IPV4:
        raise ManifestError(
            "dns_plan refused: BLOCKED_SAFETY_CONFLICT shared extra-cli/warmbly IPv4"
        )
    return (
        DnsMutation(
            op="upsert",
            type="A",
            name="smartlic.tech",
            content=target_ip,
            ttl=60,
            proxied=False,
        ),
        DnsMutation(
            op="upsert",
            type="A",
            name="www.smartlic.tech",
            content=target_ip,
            ttl=300,
            proxied=False,
        ),
        DnsMutation(op="delete_if", type="CNAME", name="www.smartlic.tech"),
    )


def rollback_dns_plan() -> tuple[DnsMutation, ...]:
    return (
        DnsMutation(
            op="upsert",
            type="A",
            name="smartlic.tech",
            content=BASELINE_APEX_A,
            ttl=60,
            proxied=False,
        ),
        DnsMutation(op="delete_if", type="A", name="www.smartlic.tech"),
        DnsMutation(
            op="upsert",
            type="CNAME",
            name="www.smartlic.tech",
            content="app.smartlic.tech",
            ttl=300,
            proxied=False,
        ),
    )


def assert_plan_safe(plan: tuple[DnsMutation, ...] | list[DnsMutation]) -> None:
    for item in plan:
        name = item.name.lower().rstrip(".")
        if name in FORBIDDEN_DNS_NAMES or name.startswith("api.") or name == "app.smartlic.tech":
            raise ManifestError(f"dns plan refused: forbidden name {item.name}")
        if name not in ALLOWED_DNS_NAMES:
            raise ManifestError(f"dns plan refused: name {item.name} is not apex/www")
        if item.type.upper() in FORBIDDEN_DNS_TYPES:
            raise ManifestError(f"dns plan refused: type {item.type}")
        if item.op not in {"upsert", "delete_if"}:
            raise ManifestError(f"dns plan refused: op {item.op}")
        if item.proxied:
            raise ManifestError("dns plan refused: proxied must be false for ACME HTTP-01")


def runtime_install_commands() -> tuple[str, ...]:
    commands = (
        "python3 -m bridge.generate --check",
        "python3 -m bridge.serve --host 127.0.0.1 --port 8765",
        "install -m 0644 bridge/generated/Caddyfile /etc/caddy/Caddyfile",
        "systemctl enable --now smartlic-bridge caddy-bridge",
        "systemctl restart smartlic-bridge",
        "systemctl restart caddy-bridge",
    )
    assert_runtime_commands_safe(commands)
    return commands


def assert_runtime_commands_safe(commands: tuple[str, ...] | list[str]) -> None:
    blob = "\n".join(commands).lower()
    for token in PRODUCT_RUNTIME_TOKENS:
        if token in blob:
            raise ManifestError(f"runtime plan refused: product token {token!r}")


def default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            payload = json.loads(raw.decode("utf-8") or "{}")
            payload["_http_status"] = getattr(resp, "status", None) or resp.getcode()
            return payload
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {"success": False, "errors": [{"message": f"HTTP {exc.code}"}]}
        payload["_http_status"] = exc.code
        return payload


def _cf_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _record_url(zone_id: str, query: Mapping[str, str] | None = None) -> str:
    base = f"{CF_API}/zones/{zone_id}/dns_records"
    if query:
        return f"{base}?{urlencode(query)}"
    return base


def apply_dns(
    plan: tuple[DnsMutation, ...] | list[DnsMutation],
    *,
    token: str | None,
    zone_id: str | None,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Apply only the pinned apex/www mutations. Fail closed without secrets."""
    assert_plan_safe(plan)
    if not token or not zone_id:
        return {
            "status": "BLOCKED_SINGLE_EXTERNAL_ACTION",
            "field": "CF_API_TOKEN" if not token else "CF_ZONE_ID",
            "applied": False,
            "mutations": 0,
            "action": SINGLE_HUMAN_ACTION,
        }
    if transport is None:
        raise ManifestError(
            "apply_dns refused: live Cloudflare transport is not attached; "
            "pass an explicit transport only after host health is proven"
        )
    zone_payload = transport("GET", _zone_url(zone_id), _cf_headers(token), None)
    zone_name = str(((zone_payload or {}).get("result") or {}).get("name") or "")
    assert_cf_zone_allowed(zone_name)
    results: list[dict[str, Any]] = []
    for item in plan:
        headers = _cf_headers(token)
        listed = transport(
            "GET",
            _record_url(zone_id, {"name": item.name, "type": item.type}),
            headers,
            None,
        )
        records = list((listed or {}).get("result") or [])
        if item.op == "delete_if":
            for row in records:
                record_id = str(row.get("id") or "")
                name = str(row.get("name") or item.name)
                if not record_id:
                    continue
                if name.lower().rstrip(".") not in ALLOWED_DNS_NAMES:
                    raise ManifestError(f"apply_dns refused delete of {name}")
                deleted = transport(
                    "DELETE",
                    f"{_record_url(zone_id)}/{record_id}",
                    headers,
                    None,
                )
                results.append({"op": "delete", "name": item.name, "ok": bool(deleted.get("success"))})
            continue
        body = json.dumps(
            {
                "type": item.type,
                "name": item.name,
                "content": item.content,
                "ttl": item.ttl,
                "proxied": False,
            }
        ).encode("utf-8")
        if records:
            record_id = str(records[0].get("id") or "")
            name = str(records[0].get("name") or item.name)
            if name.lower().rstrip(".") not in ALLOWED_DNS_NAMES:
                raise ManifestError(f"apply_dns refused patch of {name}")
            updated = transport(
                "PATCH",
                f"{_record_url(zone_id)}/{record_id}",
                headers,
                body,
            )
            results.append({"op": "patch", "name": item.name, "ok": bool(updated.get("success"))})
        else:
            created = transport("POST", _record_url(zone_id), headers, body)
            results.append({"op": "post", "name": item.name, "ok": bool(created.get("success"))})
    ok = all(row.get("ok") for row in results) if results else False
    return {
        "status": "APPLIED" if ok else "BLOCKED",
        "applied": ok,
        "mutations": len(results),
        "results": results,
    }


def live_production_probe(
    *,
    host: str,
    path: str,
    expected_location: str,
    expected_hash: str,
) -> ProductionProbe:
    import http.client
    import ssl

    if host not in LIVE_HOSTS:
        raise ManifestError(f"live probe refused host={host}")
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=20, context=ctx)
    try:
        conn.request("GET", path, headers={"Host": host, "User-Agent": "SmartLic-2115-apply/1.0"})
        resp = conn.getresponse()
        resp.read()
        return ProductionProbe(
            host=host,
            path=path,
            status=int(resp.status),
            location=resp.getheader("Location"),
            config_hash=resp.getheader("X-Bridge-Config-Hash") or "",
            source="live",
            captured_at=None,
        )
    finally:
        conn.close()
    del expected_location, expected_hash


def run_apply(
    *,
    environ: Mapping[str, str] | None = None,
    env_file: Path | None = AUTHORIZED_ENV_FILE,
    transport: Transport | None = None,
    attach_live_transport: bool = False,
    first_production_probe: ProductionProbe | None = None,
    observation_path: Path | None = None,
    observe_dns_fn: Callable[[str], DnsObservation] = observe_dns,
    observe_tls_fn: Callable[[str], TlsObservation] = observe_tls,
) -> dict[str, Any]:
    compiled = load_and_compile()
    if compiled.manifesto_sha256 != PINNED_SHA256 or compiled.config_sha256 != PINNED_CONFIG_SHA256:
        raise ManifestError("PIN_DRIFT apply refused")
    values = load_authorized_env(environ, env_file)
    presence = credential_presence(values)
    missing = missing_credentials(values)
    commands = runtime_install_commands()
    dns_current = {
        "apex": observe_dns_fn("smartlic.tech").addresses,
        "www": observe_dns_fn("www.smartlic.tech").addresses,
        "api": observe_dns_fn("api.smartlic.tech").addresses,
    }
    plan = None
    target_ip = values.get("BRIDGE_PUBLIC_IPV4")
    # Empty/degraded DNS is the cutover start state — still plan apex/www A records.
    if target_ip and is_public_ipv4(target_ip):
        plan = dns_plan(target_ip)
        assert_plan_safe(plan)
    if not dns_current["apex"]:
        tls_current = {"apex_ok": False, "www_ok": False, "skipped": True}
    else:
        tls_current = {
            "apex_ok": observe_tls_fn("smartlic.tech").ok,
            "www_ok": observe_tls_fn("www.smartlic.tech").ok,
        }
    if missing:
        status = "BLOCKED_SINGLE_EXTERNAL_ACTION"
        action = SINGLE_HUMAN_ACTION
    else:
        status = "READY_TO_APPLY"
        action = ""
    payload: dict[str, Any] = {
        "status": status,
        "campaign": "SMARTLIC-LIVE-CUTOVER-EXECUTION-02",
        "canonical_public_zone": CANONICAL_PUBLIC_ZONE,
        "manifesto_sha256": compiled.manifesto_sha256,
        "config_sha256": compiled.config_sha256,
        "pinned_commit": PINNED_COMMIT,
        "credential_presence": presence,
        "missing": list(missing),
        "dns_plan": [
            {
                "op": item.op,
                "type": item.type,
                "name": item.name,
                "ttl": item.ttl,
                "proxied": item.proxied,
                "has_content": bool(item.content),
            }
            for item in (plan or ())
        ],
        "runtime_commands": list(commands),
        "dns_current": {
            "apex_count": len(dns_current["apex"]),
            "www_count": len(dns_current["www"]),
            "api_count": len(dns_current["api"]),
            "api_unchanged_intent": True,
        },
        "tls_current": tls_current,
        "applied": False,
        "observation": None,
        "action": action,
    }

    def _observation(*, persist: bool) -> dict[str, Any]:
        result = start_observation_window(
            first_production_probe,
            compiled,
            write_path=observation_path if persist else None,
        )
        return {
            "status": result.get("status"),
            "first_production_301": result.get("first_production_301"),
            "observation_started_at": result.get("observation_started_at"),
            "observation_end": result.get("observation_end"),
            "config_sha256": result.get("config_sha256"),
            "http_status": result.get("http_status"),
            "location": result.get("location"),
            "written": result.get("written"),
        }

    if missing:
        payload["observation"] = _observation(persist=False)
        payload["residual"] = build_residual(payload, compiled=compiled)
        payload["verdict"] = payload["residual"]["verdict"]
        return json.loads(redact_secrets(json.dumps(payload, ensure_ascii=False)))

    live_transport = transport
    if live_transport is None and attach_live_transport:
        live_transport = default_transport
    if live_transport is None:
        payload["observation"] = _observation(persist=False)
        payload["residual"] = build_residual(payload, compiled=compiled)
        payload["verdict"] = payload["residual"]["verdict"]
        return json.loads(redact_secrets(json.dumps(payload, ensure_ascii=False)))
    dns_result = apply_dns(
        plan or (),
        token=values.get("CF_API_TOKEN"),
        zone_id=values.get("CF_ZONE_ID"),
        transport=live_transport,
    )
    payload["dns_result"] = {
        "status": dns_result.get("status"),
        "applied": dns_result.get("applied"),
        "mutations": dns_result.get("mutations"),
    }
    payload["applied"] = bool(dns_result.get("applied"))
    payload["status"] = str(dns_result.get("status") or payload["status"])
    payload["observation"] = _observation(persist=bool(payload["applied"]))
    if payload["applied"] and payload["observation"].get("status") == "OBSERVED":
        payload["status"] = "LIVE_CUTOVER_PROVEN_OBSERVATION_STARTED"
    payload["residual"] = build_residual(payload, compiled=compiled)
    payload["verdict"] = payload["residual"]["verdict"]
    return json.loads(redact_secrets(json.dumps(payload, ensure_ascii=False)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed live apply for #2115.")
    parser.add_argument("--env-file", type=Path, default=AUTHORIZED_ENV_FILE)
    parser.add_argument("--observation", type=Path, default=None)
    parser.add_argument("--first-production-probe", type=Path, default=None)
    parser.add_argument("--attach-live-transport", action="store_true")
    parser.add_argument("--json-only", action="store_true")
    parser.add_argument("--residual-out", type=Path, default=None)
    parser.add_argument("--operator-out", type=Path, default=None)
    args = parser.parse_args(argv)

    probe = None
    if args.first_production_probe is not None and args.first_production_probe.is_file():
        from bridge.preflight import load_probe_file

        probe = load_probe_file(args.first_production_probe)

    try:
        payload = run_apply(
            env_file=args.env_file,
            first_production_probe=probe,
            observation_path=args.observation,
            attach_live_transport=args.attach_live_transport,
        )
    except ManifestError as exc:
        print(redact_secrets(f"APPLY_BLOCKED {exc}"), file=sys.stderr)
        return 2

    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    text = redact_secrets(text)
    if args.residual_out is not None:
        residual_text = json.dumps(payload["residual"], ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        residual_text = redact_secrets(residual_text)
        args.residual_out.parent.mkdir(parents=True, exist_ok=True)
        args.residual_out.write_text(residual_text, encoding="utf-8")
    if args.operator_out is not None:
        args.operator_out.parent.mkdir(parents=True, exist_ok=True)
        args.operator_out.write_text(
            operator_one_shot_text(config_sha256=payload["config_sha256"]),
            encoding="utf-8",
        )
    if not args.json_only:
        print(
            redact_secrets(
                f"APPLY_{payload['status']} "
                f"verdict={payload.get('verdict')} "
                f"manifesto={payload['manifesto_sha256']} "
                f"config={payload['config_sha256']} "
                f"applied={payload['applied']}"
            )
        )
    sys.stdout.write(text)
    return 0 if payload["status"] == "LIVE_CUTOVER_PROVEN_OBSERVATION_STARTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
