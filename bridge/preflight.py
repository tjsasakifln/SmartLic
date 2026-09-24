#!/usr/bin/env python3
"""Fail-closed, read-only cutover preflight for SmartLic#2115.

Run this before any human DNS/TLS apply. Missing any requirement, or
divergence of the web-cfg pin/commit or bridge config hash, yields
status BLOCKED with the exact field and next action.

This module does not mutate DNS or TLS, does not call the Cloudflare
write API, and does not print secrets. first-production-301 is recorded
only from a captured live apex/www probe — never from fixture, mock,
heuristic, or loopback.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from bridge.deploy_kit import validate_deploy_kit
from bridge.errors import ManifestError
from bridge.generate import (
    GENERATED_DIR,
    compiled_from_map_file,
    emit,
    empty_retire_map,
    load_and_compile,
    probe_targets,
    rollback,
)
from bridge.pins import (
    FORBIDDEN_GENERIC_TARGETS,
    FORBIDDEN_TARGET_PATHS,
    OBSERVATION_WINDOW_DAYS,
    PINNED_CANONICAL_HOST,
    PINNED_COMMIT,
    PINNED_CONFIG_SHA256,
    PINNED_REDIRECT_COUNT,
    PINNED_SHA256,
    TARGET_HOSTNAME,
)
from bridge.policy import CompiledMap

BRIDGE_DIR = Path(__file__).resolve().parent
ROOT = BRIDGE_DIR.parent
BASELINE_APEX_A = "69.46.46.88"
BASELINE_WWW_A = "69.46.46.117"
LIVE_HOSTS = frozenset({"smartlic.tech", "www.smartlic.tech"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})
REFUSED_PROBE_SOURCES = frozenset(
    {"fixture", "mock", "heuristic", "loopback", "dry-run", "preview", "local"}
)
# Assignments only. Values that are $ENV refs or `...` placeholders stay intact.
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(CF_API_TOKEN|CF_ZONE_ID|API_TOKEN)\s*[:=]\s*(?!\$|\.{3}(?:\s|$))([^\s\"']+)"
)
# HTTP header with a literal bearer, not `Authorization: Bearer $CF_API_TOKEN`.
BEARER_LITERAL_RE = re.compile(
    r"(?i)(Authorization\s*:\s*Bearer\s+)(?!\$)(\S+)"
)
PRIVATE_KEY_RE = re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE")
# Real token prefixes only. Do not match identifiers such as cf_api_token.
TOKENISH_RE = re.compile(r"\b(?:sk_live_|sk_test_|ghp_|github_pat_)[A-Za-z0-9_\-]{8,}")

ACTIONS = {
    "BRIDGE_PUBLIC_IPV4": (
        "export BRIDGE_PUBLIC_IPV4=<public IPv4 of the chosen host>"
    ),
    "SMARTLIC_ACME_EMAIL": (
        "export SMARTLIC_ACME_EMAIL=<ops contact for Let's Encrypt>"
    ),
    "CF_API_TOKEN": (
        "export CF_API_TOKEN (local only; never commit; preflight does not call Cloudflare)"
    ),
    "CF_ZONE_ID": "export CF_ZONE_ID (local only; never commit)",
    "WEB_CFG_PIN": (
        f"restore manifesto bytes from web-cfg@{PINNED_COMMIT} "
        f"(expected {PINNED_SHA256})"
    ),
    "WEB_CFG_COMMIT": (
        f"pin map to {PINNED_COMMIT}; refuse cutover on divergence"
    ),
    "BRIDGE_CONFIG_HASH": (
        "regenerate with python3 -m bridge.generate; refuse cutover until "
        f"hash equals {PINNED_CONFIG_SHA256}"
    ),
    "WEB_CFG_DESTINATION": (
        "every ready Location must be the pinned "
        f"{PINNED_CANONICAL_HOST}/<path>; HOLD/RETIRE/unmapped never go to home"
    ),
    "DNS_CURRENT": (
        "resolve smartlic.tech and www.smartlic.tech read-only (getaddrinfo); "
        "do not mutate DNS"
    ),
    "DNS_TARGET": "export BRIDGE_PUBLIC_IPV4=<public IPv4 of the chosen host>",
    "CADDY_TLS": (
        "Caddyfile must terminate ACME SAN smartlic.tech+www and "
        "reverse_proxy 127.0.0.1:8765"
    ),
    "PORTS": "public TCP 22/80/443 only; :8765 loopback",
    "LEAST_PRIVILEGE": (
        "non-root units + nftables policy drop; validate_deploy_kit must pass"
    ),
    "BLACKBOX": (
        "launch python3 -m bridge.serve against the generated map; require one "
        "ready 301 + pinned Location and / /login HOLD as 410 with no Location"
    ),
    "ROLLBACK": (
        "run python3 -m bridge.generate --rollback on a staging dir bound to "
        "the same config hash; expect zero 301s"
    ),
    "first-production-301": (
        "after apply, capture a real probe of https://smartlic.tech/<ready> or "
        "https://www.smartlic.tech/<ready> returning 301 + pinned Location + "
        "matching X-Bridge-Config-Hash; fixture/mock/loopback refused"
    ),
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    field: str
    action: str
    detail: str = ""


@dataclass(frozen=True)
class DnsObservation:
    hostname: str
    addresses: tuple[str, ...]
    error: str | None = None


@dataclass(frozen=True)
class TlsObservation:
    hostname: str
    ok: bool
    sans: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class ProductionProbe:
    host: str
    path: str
    status: int
    location: str | None
    config_hash: str
    source: str
    captured_at: str | None = None


@dataclass(frozen=True)
class FirstProductionRecord:
    status: str
    field: str
    action: str
    detail: str = ""
    written: bool = False


@dataclass
class PreflightInputs:
    bridge_public_ipv4: str | None
    smartlic_acme_email: str | None
    cf_api_token: str | None
    cf_zone_id: str | None
    compiled: CompiledMap | None
    compile_error: str | None
    caddy_text: str
    dns_apex: DnsObservation | None = None
    dns_www: DnsObservation | None = None
    tls_apex: TlsObservation | None = None
    tls_www: TlsObservation | None = None
    skip_blackbox: bool = False
    run_live_dest_probe: bool = False
    first_production_probe: ProductionProbe | None = None
    blackbox_dir: Path | None = None


@dataclass
class PreflightReport:
    status: str
    field: str
    action: str
    manifesto_sha256: str
    config_sha256: str
    pinned_commit: str
    dns_mutated: bool
    tls_mutated: bool
    checks: list[CheckResult] = field(default_factory=list)
    apply_commands: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    first_production_301: dict[str, Any] = field(default_factory=dict)
    blackbox: dict[str, Any] | None = None
    dns: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "status": self.status,
            "field": self.field,
            "action": self.action,
            "manifesto_sha256": self.manifesto_sha256,
            "config_sha256": self.config_sha256,
            "pinned_commit": self.pinned_commit,
            "dns_mutated": self.dns_mutated,
            "tls_mutated": self.tls_mutated,
            "checks": [asdict(item) for item in self.checks],
            "apply_commands": list(self.apply_commands),
            "rollback_commands": list(self.rollback_commands),
            "first_production_301": dict(self.first_production_301),
            "blackbox": self.blackbox,
            "dns": dict(self.dns),
            "tls": dict(self.tls),
        }
        return json.loads(redact_secrets(json.dumps(payload, ensure_ascii=False)))


def _pass(name: str, field_name: str, detail: str = "") -> CheckResult:
    return CheckResult(name=name, status="PASS", field=field_name, action="", detail=detail)


def _blocked(name: str, field_name: str, detail: str = "") -> CheckResult:
    return CheckResult(
        name=name,
        status="BLOCKED",
        field=field_name,
        action=ACTIONS[field_name],
        detail=detail,
    )


def env_value(name: str, environ: Mapping[str, str] | None = None) -> str | None:
    source = os.environ if environ is None else environ
    raw = source.get(name)
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def redact_secrets(text: str) -> str:
    """Strip leaked token values. Keep $ENV command templates and identifiers."""
    redacted = SECRET_ASSIGN_RE.sub(r"\1=<redacted>", text)
    redacted = BEARER_LITERAL_RE.sub(r"\1<redacted>", redacted)
    redacted = PRIVATE_KEY_RE.sub("BEGIN <redacted-key>", redacted)
    redacted = TOKENISH_RE.sub("<redacted-token>", redacted)
    return redacted


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return bool(ip.is_global)


def check_bridge_public_ipv4(value: str | None) -> CheckResult:
    if not value:
        return _blocked("bridge_public_ipv4", "BRIDGE_PUBLIC_IPV4", "missing")
    if not is_public_ipv4(value):
        return _blocked(
            "bridge_public_ipv4",
            "BRIDGE_PUBLIC_IPV4",
            "not a public IPv4",
        )
    return _pass("bridge_public_ipv4", "BRIDGE_PUBLIC_IPV4", value)


def check_acme_email(value: str | None) -> CheckResult:
    if not value:
        return _blocked("smartlic_acme_email", "SMARTLIC_ACME_EMAIL", "missing")
    if " " in value or value.count("@") != 1:
        return _blocked("smartlic_acme_email", "SMARTLIC_ACME_EMAIL", "invalid")
    local, _, domain = value.partition("@")
    if not local or "." not in domain:
        return _blocked("smartlic_acme_email", "SMARTLIC_ACME_EMAIL", "invalid")
    return _pass("smartlic_acme_email", "SMARTLIC_ACME_EMAIL", "set")


def check_cloudflare_token(value: str | None) -> CheckResult:
    if not value:
        return _blocked("cf_api_token", "CF_API_TOKEN", "missing")
    return _pass("cf_api_token", "CF_API_TOKEN", "present")


def check_cloudflare_zone(value: str | None) -> CheckResult:
    if not value:
        return _blocked("cf_zone_id", "CF_ZONE_ID", "missing")
    return _pass("cf_zone_id", "CF_ZONE_ID", "present")


def check_webcfg_pin(*, manifesto_sha256: str, pinned_commit: str) -> CheckResult:
    if manifesto_sha256 != PINNED_SHA256:
        return _blocked(
            "webcfg_pin",
            "WEB_CFG_PIN",
            f"obtained={manifesto_sha256} expected={PINNED_SHA256}",
        )
    if pinned_commit != PINNED_COMMIT:
        return _blocked(
            "webcfg_commit",
            "WEB_CFG_COMMIT",
            f"obtained={pinned_commit} expected={PINNED_COMMIT}",
        )
    return _pass(
        "webcfg_pin",
        "WEB_CFG_PIN",
        f"sha256={manifesto_sha256} commit={pinned_commit}",
    )


def check_config_hash(observed: str) -> CheckResult:
    if observed != PINNED_CONFIG_SHA256:
        return _blocked(
            "bridge_config_hash",
            "BRIDGE_CONFIG_HASH",
            f"obtained={observed} expected={PINNED_CONFIG_SHA256}",
        )
    return _pass("bridge_config_hash", "BRIDGE_CONFIG_HASH", observed)


def check_destinations(compiled: CompiledMap) -> CheckResult:
    if len(compiled.redirects) != PINNED_REDIRECT_COUNT:
        return _blocked(
            "webcfg_destination",
            "WEB_CFG_DESTINATION",
            f"redirects={len(compiled.redirects)} expected={PINNED_REDIRECT_COUNT}",
        )
    for rule in compiled.redirects:
        target = rule.target_url
        if target in FORBIDDEN_GENERIC_TARGETS:
            return _blocked(
                "webcfg_destination",
                "WEB_CFG_DESTINATION",
                f"{rule.path} generic target {target}",
            )
        parts = urlsplit(target)
        if parts.scheme != "https" or (parts.hostname or "") != TARGET_HOSTNAME:
            return _blocked(
                "webcfg_destination",
                "WEB_CFG_DESTINATION",
                f"{rule.path} host {parts.hostname!r} is not {TARGET_HOSTNAME}",
            )
        path = parts.path or "/"
        if path in FORBIDDEN_TARGET_PATHS or path in {"", "/"}:
            return _blocked(
                "webcfg_destination",
                "WEB_CFG_DESTINATION",
                f"{rule.path} forbidden path {path}",
            )
        if not target.startswith(PINNED_CANONICAL_HOST + "/"):
            return _blocked(
                "webcfg_destination",
                "WEB_CFG_DESTINATION",
                f"{rule.path} not under {PINNED_CANONICAL_HOST}/",
            )
    return _pass(
        "webcfg_destination",
        "WEB_CFG_DESTINATION",
        f"redirects={len(compiled.redirects)} host={TARGET_HOSTNAME}",
    )


def check_dns_current_vs_target(
    *,
    apex: DnsObservation | None,
    www: DnsObservation | None,
    target_ip: str | None,
) -> CheckResult:
    if not target_ip:
        return _blocked("dns_target", "DNS_TARGET", "BRIDGE_PUBLIC_IPV4 missing")
    if not is_public_ipv4(target_ip):
        return _blocked("dns_target", "DNS_TARGET", "target is not a public IPv4")
    if apex is None or not apex.addresses:
        return _blocked(
            "dns_current",
            "DNS_CURRENT",
            apex.error if apex is not None else "smartlic.tech not observed",
        )
    if www is None or not www.addresses:
        return _blocked(
            "dns_current",
            "DNS_CURRENT",
            www.error if www is not None else "www.smartlic.tech not observed",
        )
    detail = (
        f"current_apex={','.join(apex.addresses)} "
        f"current_www={','.join(www.addresses)} "
        f"target={target_ip} "
        f"baseline_apex={BASELINE_APEX_A} baseline_www={BASELINE_WWW_A}"
    )
    return _pass("dns_current_vs_target", "DNS_CURRENT", detail)


def check_tls_acme(*, acme_email: str | None, caddy_text: str) -> CheckResult:
    email = check_acme_email(acme_email)
    if email.status == "BLOCKED":
        return _blocked("tls_acme", "SMARTLIC_ACME_EMAIL", email.detail)
    from bridge.generate import assert_terminator_safe

    try:
        assert_terminator_safe(caddy_text)
    except ManifestError as exc:
        return _blocked("tls_acme", "CADDY_TLS", str(exc))
    if "{$SMARTLIC_ACME_EMAIL}" not in caddy_text:
        return _blocked("tls_acme", "CADDY_TLS", "ACME email placeholder missing")
    return _pass("tls_acme", "CADDY_TLS", "caddy ACME SAN plan present")


def check_ports(*, caddy_text: str, firewall_text: str, bridge_unit: str) -> CheckResult:
    from bridge.deploy_kit import (
        assert_bridge_unit_safe,
        assert_firewall_safe,
    )
    from bridge.generate import assert_terminator_safe

    try:
        assert_terminator_safe(caddy_text)
        assert_bridge_unit_safe(bridge_unit)
        assert_firewall_safe(firewall_text)
    except ManifestError as exc:
        return _blocked("ports", "PORTS", str(exc))
    if "reverse_proxy 127.0.0.1:8765" not in caddy_text:
        return _blocked("ports", "PORTS", "Caddy must proxy only 127.0.0.1:8765")
    if "8765" in firewall_text:
        return _blocked("ports", "PORTS", ":8765 must stay loopback")
    return _pass("ports", "PORTS", "22/80/443 public; 8765 loopback")


def check_least_privilege(root: Path | None = None) -> CheckResult:
    try:
        validate_deploy_kit(root)
    except ManifestError as exc:
        return _blocked("least_privilege", "LEAST_PRIVILEGE", str(exc))
    return _pass("least_privilege", "LEAST_PRIVILEGE", "validate_deploy_kit ok")


def observe_dns(hostname: str) -> DnsObservation:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        addrs = tuple(sorted({item[4][0] for item in infos}))
        if not addrs:
            return DnsObservation(hostname=hostname, addresses=(), error="no A records")
        return DnsObservation(hostname=hostname, addresses=addrs)
    except OSError as exc:
        return DnsObservation(hostname=hostname, addresses=(), error=str(exc))


def observe_tls(hostname: str, timeout: float = 8.0) -> TlsObservation:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
        sans = tuple(sorted(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"))
        return TlsObservation(hostname=hostname, ok=True, sans=sans)
    except Exception as exc:  # noqa: BLE001 — observation must surface any failure
        return TlsObservation(
            hostname=hostname,
            ok=False,
            error=f"{type(exc).__name__}",
        )


def render_apply_commands(target_ip: str | None) -> list[str]:
    dest = target_ip or "$BRIDGE_PUBLIC_IPV4"
    return [
        "# APPLY — owner-only; preflight does not execute these",
        "# export CF_API_TOKEN=... CF_ZONE_ID=... BRIDGE_PUBLIC_IPV4=...",
        (
            'curl -sS -H "Authorization: Bearer $CF_API_TOKEN" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records'
            '?name=smartlic.tech,www.smartlic.tech"'
        ),
        (
            'curl -sS -X POST -H "Authorization: Bearer $CF_API_TOKEN" '
            '-H "Content-Type: application/json" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" '
            f'--data \'{{"type":"A","name":"www","content":"{dest}","ttl":300,"proxied":false}}\''
        ),
        (
            'curl -sS -X DELETE -H "Authorization: Bearer $CF_API_TOKEN" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$WWW_CNAME_ID"'
        ),
        (
            'curl -sS -X PATCH -H "Authorization: Bearer $CF_API_TOKEN" '
            '-H "Content-Type: application/json" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$APEX_A_ID" '
            f'--data \'{{"type":"A","name":"smartlic.tech","content":"{dest}","ttl":60,"proxied":false}}\''
        ),
    ]


def render_rollback_commands() -> list[str]:
    return [
        "# ROLLBACK — config (executed in staging by preflight; not live DNS)",
        "python3 -m bridge.generate --rollback",
        "# ROLLBACK — DNS (printed only; restore 2026-08-14/15 baseline)",
        (
            'curl -sS -X PATCH -H "Authorization: Bearer $CF_API_TOKEN" '
            '-H "Content-Type: application/json" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$APEX_A_ID" '
            f'--data \'{{"type":"A","name":"smartlic.tech","content":"{BASELINE_APEX_A}","ttl":60,"proxied":false}}\''
        ),
        (
            'curl -sS -X DELETE -H "Authorization: Bearer $CF_API_TOKEN" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$WWW_A_ID"'
        ),
        (
            'curl -sS -X POST -H "Authorization: Bearer $CF_API_TOKEN" '
            '-H "Content-Type: application/json" '
            '"https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" '
            '--data \'{"type":"CNAME","name":"www","content":"app.smartlic.tech.","ttl":300,"proxied":false}\''
        ),
    ]


def register_first_production_301(
    probe: ProductionProbe | None,
    compiled: CompiledMap | None,
    *,
    write_path: Path | None = None,
) -> FirstProductionRecord:
    """Write first-production-301 only from a real post-apply live probe."""
    action = ACTIONS["first-production-301"]
    if probe is None:
        return FirstProductionRecord(
            status="UNOBSERVED",
            field="first-production-301",
            action=action,
            detail="no live post-apply probe supplied",
            written=False,
        )
    source = (probe.source or "").strip().lower()
    if source in REFUSED_PROBE_SOURCES:
        return FirstProductionRecord(
            status="BLOCKED",
            field="first-production-301",
            action=action,
            detail=f"refused source={source}",
            written=False,
        )
    host = (probe.host or "").split(":", 1)[0].lower()
    if host in LOOPBACK_HOSTS:
        return FirstProductionRecord(
            status="BLOCKED",
            field="first-production-301",
            action=action,
            detail=f"refused loopback host={host}",
            written=False,
        )
    if host not in LIVE_HOSTS:
        return FirstProductionRecord(
            status="BLOCKED",
            field="first-production-301",
            action=action,
            detail=f"host {host!r} is not live apex/www",
            written=False,
        )
    if compiled is None:
        return FirstProductionRecord(
            status="BLOCKED",
            field="BRIDGE_CONFIG_HASH",
            action=ACTIONS["BRIDGE_CONFIG_HASH"],
            detail="compiled map missing; cannot bind probe to pin",
            written=False,
        )
    if probe.status != 301:
        return FirstProductionRecord(
            status="BLOCKED",
            field="first-production-301",
            action=action,
            detail=f"status={probe.status} expected=301",
            written=False,
        )
    if probe.config_hash != compiled.config_sha256:
        return FirstProductionRecord(
            status="BLOCKED",
            field="BRIDGE_CONFIG_HASH",
            action=ACTIONS["BRIDGE_CONFIG_HASH"],
            detail=(
                f"probe config {probe.config_hash} != "
                f"compiled {compiled.config_sha256}"
            ),
            written=False,
        )
    location = probe.location or ""
    allowed = {rule.target_url for rule in compiled.redirects}
    if location not in allowed:
        return FirstProductionRecord(
            status="BLOCKED",
            field="WEB_CFG_DESTINATION",
            action=ACTIONS["WEB_CFG_DESTINATION"],
            detail=f"Location {location!r} is not a pinned ready target",
            written=False,
        )
    record = {
        "status": "OBSERVED",
        "field": "first-production-301",
        "host": host,
        "path": probe.path,
        "http_status": probe.status,
        "location": location,
        "config_sha256": probe.config_hash,
        "manifesto_sha256": compiled.manifesto_sha256,
        "source": source,
        "captured_at": probe.captured_at,
    }
    written = False
    if write_path is not None:
        write_path.parent.mkdir(parents=True, exist_ok=True)
        write_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written = True
    return FirstProductionRecord(
        status="OBSERVED",
        field="first-production-301",
        action="",
        detail=f"live {host}{probe.path} → {location}",
        written=written,
    )


def _parse_probe_time(raw: str | None, fallback: datetime) -> datetime:
    if not raw:
        return fallback
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return fallback


def start_observation_window(
    probe: ProductionProbe | None,
    compiled: CompiledMap | None,
    *,
    write_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist the 28-day window only from a real production 301 probe.

    Loopback/fixture/mock probes cannot set observation_started_at.
    """
    moment = now or datetime.now(timezone.utc)
    record = register_first_production_301(probe, compiled)
    if record.status != "OBSERVED" or compiled is None or probe is None:
        payload = {
            "status": record.status,
            "field": record.field,
            "detail": record.detail,
            "first_production_301": record.status,
            "observation_started_at": None,
            "observation_end": None,
            "config_sha256": None,
            "manifesto_sha256": None,
            "written": False,
        }
        return payload
    started = _parse_probe_time(probe.captured_at, moment)
    ended = started + timedelta(days=OBSERVATION_WINDOW_DAYS)
    payload = {
        "status": "OBSERVED",
        "field": "first-production-301",
        "detail": record.detail,
        "first_production_301": "OBSERVED",
        "observation_started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observation_end": ended.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "captured_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config_sha256": probe.config_hash,
        "manifesto_sha256": compiled.manifesto_sha256,
        "host": (probe.host or "").split(":", 1)[0].lower(),
        "path": probe.path,
        "http_status": probe.status,
        "location": probe.location,
        "source": probe.source,
        "written": False,
    }
    if write_path is not None:
        write_path.parent.mkdir(parents=True, exist_ok=True)
        write_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        payload["written"] = True
    return payload


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _wait_serve(proc: subprocess.Popen[str], timeout: float = 5.0) -> str:
    deadline = time.time() + timeout
    assert proc.stdout is not None
    buf = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            raise ManifestError(f"bridge.serve exited {proc.returncode}: {err}")
        line = proc.stdout.readline()
        buf += line
        if "SERVE_OK" in buf:
            return buf
        time.sleep(0.05)
    raise ManifestError(f"bridge.serve did not become ready: {buf!r}")


def _hit(port: int, path: str) -> tuple[int, str | None, str]:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers={"Host": "smartlic.tech"})
        resp = conn.getresponse()
        resp.read()
        return resp.status, resp.getheader("Location"), resp.getheader("X-Bridge-Config-Hash") or ""
    finally:
        conn.close()


def _stop(proc: subprocess.Popen[str]) -> None:
    proc.terminate()
    try:
        proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=3)


def run_local_blackbox(compiled: CompiledMap, workdir: Path) -> dict[str, Any]:
    """Launch the shipped serve entry against a temp map, then rollback it."""
    active = workdir / "active"
    emit(compiled, active)
    emit(empty_retire_map(compiled.manifesto_sha256), active / "previous")
    map_path = active / "bridge-map.json"
    ready = compiled.redirects[0]
    hold = compiled.holds[0] if compiled.holds else "/not-a-ready-path-2115"

    def launch(port: int) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "bridge.serve",
                "--map",
                str(map_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    port = _free_port()
    proc = launch(port)
    try:
        banner = _wait_serve(proc)
        ready_status, ready_loc, ready_hash = _hit(port, ready.path)
        slash_status, slash_loc, _ = _hit(port, "/")
        login_status, login_loc, _ = _hit(port, "/login")
        hold_status, hold_loc, _ = _hit(port, hold)
    finally:
        _stop(proc)

    ready_ok = (
        ready_status == 301
        and ready_loc == ready.target_url
        and ready_hash == compiled.config_sha256
    )
    gone_ok = (
        slash_status == 410
        and slash_loc is None
        and login_status == 410
        and login_loc is None
        and hold_status == 410
        and hold_loc is None
    )
    if not ready_ok or not gone_ok:
        return {
            "status": "BLOCKED",
            "field": "BLACKBOX",
            "action": ACTIONS["BLACKBOX"],
            "ready_path": ready.path,
            "ready_status": ready_status,
            "ready_location": ready_loc,
            "slash_status": slash_status,
            "login_status": login_status,
            "hold_path": hold,
            "hold_status": hold_status,
            "config_sha256": ready_hash,
            "banner": banner,
            "rollback": None,
        }

    rollback(active)
    rolled = compiled_from_map_file(active / "bridge-map.json")
    rb_port = _free_port()
    rb_proc = launch(rb_port)
    try:
        rb_banner = _wait_serve(rb_proc)
        rb_ready_status, rb_ready_loc, rb_hash = _hit(rb_port, ready.path)
        zeros = True
        for rule in compiled.redirects:
            st, loc, _cfg = _hit(rb_port, rule.path)
            if st != 410 or loc is not None:
                zeros = False
                break
    finally:
        _stop(rb_proc)

    rollback_ok = (
        zeros
        and rb_ready_status == 410
        and rb_ready_loc is None
        and rolled.redirects == ()
        and rolled.manifesto_sha256 == compiled.manifesto_sha256
        and rolled.config_sha256 != compiled.config_sha256
    )
    rollback_payload = {
        "status": "PASS" if rollback_ok else "BLOCKED",
        "field": "ROLLBACK",
        "action": "" if rollback_ok else ACTIONS["ROLLBACK"],
        "from_config_sha256": compiled.config_sha256,
        "rollback_config_sha256": rolled.config_sha256,
        "manifesto_sha256": rolled.manifesto_sha256,
        "redirects": len(rolled.redirects),
        "ready_path_status": rb_ready_status,
        "ready_path_location": rb_ready_loc,
        "banner": rb_banner,
    }
    return {
        "status": "PASS" if rollback_ok else "BLOCKED",
        "field": "BLACKBOX" if rollback_ok else "ROLLBACK",
        "action": "" if rollback_ok else ACTIONS["ROLLBACK"],
        "ready_path": ready.path,
        "ready_status": ready_status,
        "ready_location": ready_loc,
        "slash_status": slash_status,
        "login_status": login_status,
        "hold_path": hold,
        "hold_status": hold_status,
        "config_sha256": compiled.config_sha256,
        "manifesto_sha256": compiled.manifesto_sha256,
        "banner": banner,
        "rollback": rollback_payload,
    }


def load_probe_file(path: Path) -> ProductionProbe:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ProductionProbe(
        host=str(data.get("host") or ""),
        path=str(data.get("path") or ""),
        status=int(data.get("status") or 0),
        location=data.get("location"),
        config_hash=str(data.get("config_hash") or data.get("config_sha256") or ""),
        source=str(data.get("source") or "fixture"),
        captured_at=data.get("captured_at"),
    )


def run_preflight(inputs: PreflightInputs) -> PreflightReport:
    checks: list[CheckResult] = []
    compiled = inputs.compiled
    manifesto = compiled.manifesto_sha256 if compiled else ""
    config_hash = compiled.config_sha256 if compiled else ""

    checks.append(check_bridge_public_ipv4(inputs.bridge_public_ipv4))
    checks.append(check_acme_email(inputs.smartlic_acme_email))
    checks.append(check_cloudflare_token(inputs.cf_api_token))
    checks.append(check_cloudflare_zone(inputs.cf_zone_id))

    if inputs.compile_error or compiled is None:
        checks.append(
            _blocked(
                "webcfg_pin",
                "WEB_CFG_PIN",
                inputs.compile_error or "compiled map missing",
            )
        )
    else:
        map_commit = PINNED_COMMIT
        map_file = GENERATED_DIR / "bridge-map.json"
        if map_file.is_file():
            try:
                map_commit = str(json.loads(map_file.read_text(encoding="utf-8"))["pinned_commit"])
            except (OSError, KeyError, json.JSONDecodeError, TypeError):
                map_commit = ""
        checks.append(
            check_webcfg_pin(
                manifesto_sha256=compiled.manifesto_sha256,
                pinned_commit=map_commit,
            )
        )
        checks.append(check_config_hash(compiled.config_sha256))
        checks.append(check_destinations(compiled))
        if inputs.run_live_dest_probe:
            try:
                probe_targets(compiled)
                checks.append(
                    _pass("webcfg_destination_live", "WEB_CFG_DESTINATION", "ready targets HTTPS 200")
                )
            except ManifestError as exc:
                checks.append(_blocked("webcfg_destination_live", "WEB_CFG_DESTINATION", str(exc)))

    checks.append(check_tls_acme(acme_email=inputs.smartlic_acme_email, caddy_text=inputs.caddy_text))
    firewall = (BRIDGE_DIR / "deploy" / "nftables.conf").read_text(encoding="utf-8")
    unit = (BRIDGE_DIR / "deploy" / "smartlic-bridge.service").read_text(encoding="utf-8")
    checks.append(check_ports(caddy_text=inputs.caddy_text, firewall_text=firewall, bridge_unit=unit))
    checks.append(check_least_privilege(BRIDGE_DIR))
    checks.append(
        check_dns_current_vs_target(
            apex=inputs.dns_apex,
            www=inputs.dns_www,
            target_ip=inputs.bridge_public_ipv4,
        )
    )

    blackbox: dict[str, Any] | None = None
    if inputs.skip_blackbox:
        blackbox = {"status": "SKIPPED", "field": "BLACKBOX", "action": ACTIONS["BLACKBOX"]}
    elif compiled is None:
        checks.append(_blocked("blackbox", "BLACKBOX", "compiled map missing"))
    else:
        workdir = inputs.blackbox_dir
        tmp_ctx = None
        if workdir is None:
            tmp_ctx = tempfile.TemporaryDirectory()
            workdir = Path(tmp_ctx.name)
        try:
            blackbox = run_local_blackbox(compiled, workdir)
        finally:
            if tmp_ctx is not None:
                tmp_ctx.cleanup()
        if blackbox.get("status") != "PASS":
            field_name = str(blackbox.get("field") or "BLACKBOX")
            checks.append(
                CheckResult(
                    name="blackbox",
                    status="BLOCKED",
                    field=field_name,
                    action=str(blackbox.get("action") or ACTIONS.get(field_name, ACTIONS["BLACKBOX"])),
                    detail=f"ready_status={blackbox.get('ready_status')} rollback={blackbox.get('rollback')}",
                )
            )
        else:
            checks.append(
                _pass(
                    "blackbox",
                    "BLACKBOX",
                    f"ready={blackbox.get('ready_path')} rollback_hash="
                    f"{(blackbox.get('rollback') or {}).get('rollback_config_sha256')}",
                )
            )

    first = register_first_production_301(inputs.first_production_probe, compiled)
    first_payload = asdict(first)

    blocked = next((item for item in checks if item.status == "BLOCKED"), None)
    if blocked is None:
        status = "READY"
        field_name = "APPLY_PREREQS"
        action = (
            "owner may apply the printed Cloudflare records; "
            "first-production-301 remains unobserved until a live post-apply probe"
        )
    else:
        status = "BLOCKED"
        field_name = blocked.field
        action = blocked.action

    dns = {
        "apex": asdict(inputs.dns_apex) if inputs.dns_apex else None,
        "www": asdict(inputs.dns_www) if inputs.dns_www else None,
        "target": inputs.bridge_public_ipv4,
        "baseline_apex": BASELINE_APEX_A,
        "baseline_www": BASELINE_WWW_A,
    }
    tls = {
        "apex": asdict(inputs.tls_apex) if inputs.tls_apex else None,
        "www": asdict(inputs.tls_www) if inputs.tls_www else None,
        "note": "read-only observation; Railway SAN mismatch is expected before apply",
    }
    return PreflightReport(
        status=status,
        field=field_name,
        action=action,
        manifesto_sha256=manifesto or PINNED_SHA256,
        config_sha256=config_hash or PINNED_CONFIG_SHA256,
        pinned_commit=PINNED_COMMIT,
        dns_mutated=False,
        tls_mutated=False,
        checks=checks,
        apply_commands=render_apply_commands(inputs.bridge_public_ipv4),
        rollback_commands=render_rollback_commands(),
        first_production_301=first_payload,
        blackbox=blackbox,
        dns=dns,
        tls=tls,
    )


def try_load_compiled() -> tuple[CompiledMap | None, str | None]:
    try:
        return load_and_compile(), None
    except ManifestError as exc:
        return None, str(exc)


def banner_line(report: PreflightReport) -> str:
    token = "PREFLIGHT_OK" if report.status == "READY" else "PREFLIGHT_BLOCKED"
    return f"{token} field={report.field} action={report.action}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only #2115 cutover preflight. Does not apply DNS/TLS."
    )
    parser.add_argument("--skip-blackbox", action="store_true")
    parser.add_argument(
        "--skip-live",
        action="store_true",
        help="skip read-only DNS/TLS observe and live destination probe",
    )
    parser.add_argument("--first-production-probe", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args(argv)

    compiled, compile_error = try_load_compiled()
    caddy_path = GENERATED_DIR / "Caddyfile"
    caddy_text = caddy_path.read_text(encoding="utf-8") if caddy_path.is_file() else ""

    probe = None
    if args.first_production_probe is not None:
        probe = load_probe_file(args.first_production_probe)

    dns_apex = None if args.skip_live else observe_dns("smartlic.tech")
    dns_www = None if args.skip_live else observe_dns("www.smartlic.tech")
    tls_apex = None if args.skip_live else observe_tls("smartlic.tech")
    tls_www = None if args.skip_live else observe_tls("www.smartlic.tech")

    inputs = PreflightInputs(
        bridge_public_ipv4=env_value("BRIDGE_PUBLIC_IPV4"),
        smartlic_acme_email=env_value("SMARTLIC_ACME_EMAIL"),
        cf_api_token=env_value("CF_API_TOKEN"),
        cf_zone_id=env_value("CF_ZONE_ID"),
        compiled=compiled,
        compile_error=compile_error,
        caddy_text=caddy_text,
        dns_apex=dns_apex,
        dns_www=dns_www,
        tls_apex=tls_apex,
        tls_www=tls_www,
        skip_blackbox=args.skip_blackbox,
        run_live_dest_probe=not args.skip_live,
        first_production_probe=probe,
    )
    report = run_preflight(inputs)
    payload = report.to_dict()
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    text = redact_secrets(text)
    line = redact_secrets(banner_line(report))
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    if args.json_only:
        sys.stdout.write(text)
    else:
        sys.stdout.write(line + "\n")
        sys.stdout.write(text)
    return 0 if report.status == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
