#!/usr/bin/env python3
"""Fail-closed validator and deterministic generator for the #2115 bridge.

Reads the hash-pinned manifesto. Emits generated/bridge-map.json + Caddyfile.
Refuses dirty, incomplete, duplicated, wildcard, or generic-home targets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bridge.errors import ManifestError
from bridge.pins import (
    BRIDGE_OWNER,
    DEFAULT_STATUS,
    FAIL_CLOSED_DECISIONS,
    FORBIDDEN_GENERIC_TARGETS,
    FORBIDDEN_TARGET_PATHS,
    HOLD_DECISIONS,
    OBSERVATION_WINDOW_DAYS,
    PINNED_CANONICAL_HOST,
    PINNED_COMMIT,
    PINNED_HOLD_COUNT,
    PINNED_IGNORE_COUNT,
    PINNED_LEGAL_COUNT,
    PINNED_LEGACY_HOST,
    PINNED_MIGRATE_COUNT,
    PINNED_REDIRECT_COUNT,
    PINNED_RETIRE_COUNT,
    PINNED_SCHEMA,
    PINNED_SHA256,
    PINNED_VERSION,
    REDIRECT_DECISIONS,
    REDIRECT_STATUS,
    TARGET_HOSTNAME,
)
from bridge.policy import CompiledMap, RedirectRule, normalize_path

BRIDGE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = BRIDGE_DIR / "manifest" / "manifesto.v1.json"
GENERATED_DIR = BRIDGE_DIR / "generated"
PREVIOUS_DIR = GENERATED_DIR / "previous"

REQUIRED_ENTRY_FIELDS = (
    "legacy_url",
    "decision",
    "status",
    "expected_http",
    "owner",
    "bridge_owner",
    "rollback",
    "removal_trigger",
    "query_string_rule",
    "family",
)
REQUIRED_REDIRECT_FIELDS = (
    "target_url",
    "expected_canonical",
    "semantic_equivalence",
    "monitoring",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest_bytes(path: Path = MANIFEST_PATH) -> bytes:
    if not path.is_file():
        raise ManifestError(
            f"manifesto ausente: {path}. Desbloqueio: vendor o ficheiro pinado "
            f"de web-cfg@{PINNED_COMMIT} ({PINNED_SHA256})."
        )
    return path.read_bytes()


def assert_pinned_hash(raw: bytes) -> str:
    digest = sha256_bytes(raw)
    if digest != PINNED_SHA256:
        raise ManifestError(
            f"hash do manifesto diverge do pin. obtido={digest} "
            f"esperado={PINNED_SHA256}. Não emitir configuração. "
            "Desbloqueio: restaurar os bytes publicados em "
            f"web-cfg@{PINNED_COMMIT}."
        )
    return digest


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ManifestError(message)


def validate_schema(data: Any) -> None:
    _require(isinstance(data, dict), "manifesto não é um objeto JSON")
    meta = data.get("meta")
    entries = data.get("entries")
    _require(isinstance(meta, dict), "meta ausente ou inválido")
    _require(isinstance(entries, list), "entries ausente ou inválido")
    _require(meta.get("version") == PINNED_VERSION, "meta.version ausente ou diferente de v2")
    _require(meta.get("schema") == PINNED_SCHEMA, "meta.schema ausente ou diferente do pin")
    _require(
        meta.get("canonical_public_host") == PINNED_CANONICAL_HOST,
        "canonical_public_host deve ser https://confenge.com.br",
    )
    _require(
        meta.get("legacy_host") == PINNED_LEGACY_HOST,
        "legacy_host deve ser https://smartlic.tech",
    )
    pinned_total = (
        PINNED_REDIRECT_COUNT
        + PINNED_RETIRE_COUNT
        + PINNED_HOLD_COUNT
        + PINNED_MIGRATE_COUNT
        + PINNED_IGNORE_COUNT
        + PINNED_LEGAL_COUNT
    )
    _require(len(entries) == pinned_total, "contagem total de entries diverge do pin")

    seen_legacy: set[str] = set()
    redirect_n = 0
    retire_n = 0
    hold_n = 0
    migrate_n = 0
    ignore_n = 0
    legal_n = 0
    persist_sets: set[tuple[str, ...]] = set()

    for index, entry in enumerate(entries):
        _require(isinstance(entry, dict), f"entry[{index}] não é objeto")
        for field in REQUIRED_ENTRY_FIELDS:
            _require(field in entry, f"entry[{index}] sem campo obrigatório {field}")

        legacy = entry["legacy_url"]
        _require(isinstance(legacy, str), f"legacy_url inválido: {legacy!r}")
        legacy_parts = urlsplit(legacy)
        legacy_origin_error = (
            "legacy_url deve usar exatamente a origem https://smartlic.tech, "
            "sem credenciais, porta, query ou fragment: "
            f"{legacy!r}"
        )
        _require(
            legacy_parts.scheme == "https"
            and legacy_parts.hostname == "smartlic.tech"
            and legacy_parts.port is None
            and legacy_parts.username is None
            and legacy_parts.password is None
            and not legacy_parts.query
            and not legacy_parts.fragment,
            legacy_origin_error,
        )
        _require("*" not in legacy, f"wildcard proibido em legacy_url: {legacy}")
        path = normalize_path(legacy_parts.path)
        _require(path not in seen_legacy, f"duplicata de path legado: {path}")
        seen_legacy.add(path)

        decision = entry["decision"]
        qrule = entry.get("query_string_rule") or {}
        _require(isinstance(qrule, dict), f"query_string_rule inválido em {legacy}")
        persist = tuple(qrule.get("persist") or ())

        if decision in REDIRECT_DECISIONS:
            if decision == "MIGRATE":
                migrate_n += 1
            else:
                redirect_n += 1
            for field in REQUIRED_REDIRECT_FIELDS:
                _require(entry.get(field), f"{decision} {legacy} sem {field}")
            _require(entry.get("status") == "ready", f"{decision} {legacy} não está ready")
            _require(entry.get("expected_http") == REDIRECT_STATUS, f"{decision} {legacy} expected_http != 301")
            _require(persist, f"{decision} {legacy} sem allowlist de query")
            persist_sets.add(persist)
            target = entry.get("target_url") or entry.get("target")
            canon = entry.get("expected_canonical") or entry.get("destination_canonical")
            _assert_safe_target(target, legacy)
            _assert_safe_target(canon, legacy)
            monitoring = entry["monitoring"]
            _require(isinstance(monitoring, dict), f"monitoring inválido em {legacy}")
            _require(
                int(monitoring.get("window_days") or 0) == OBSERVATION_WINDOW_DAYS,
                f"window_days deve ser {OBSERVATION_WINDOW_DAYS} em {legacy}",
            )
            _require(entry.get("bridge_owner"), f"bridge_owner ausente em {legacy}")
            _require(entry.get("rollback"), f"rollback ausente em {legacy}")
            _require(entry.get("removal_trigger"), f"removal_trigger ausente em {legacy}")
        elif decision in FAIL_CLOSED_DECISIONS:
            target = entry.get("target_url") if "target_url" in entry else entry.get("target")
            _require(target in (None, ""), f"{decision} {legacy} não pode ter target ({target!r})")
            _require(entry.get("expected_http") == DEFAULT_STATUS, f"{decision} {legacy} expected_http != 410")
            if decision in HOLD_DECISIONS:
                hold_n += 1
                _require(entry.get("status") == "hold", f"HOLD {legacy} status != hold")
                _require((entry.get("skip_reason") or "").strip(), f"HOLD {legacy} sem skip_reason")
                intended = (entry.get("intended_future_surface") or "").strip()
                _require(intended, f"HOLD {legacy} sem intended_future_surface")
                _require(
                    not intended.startswith("https://"),
                    f"HOLD {legacy} não pode pinhar URL viva em intended_future_surface",
                )
            elif decision in {"IGNORE_NONCANONICAL"}:
                ignore_n += 1
            elif decision in {"LEGAL_SECURITY_HOLD"}:
                legal_n += 1
            else:
                retire_n += 1
                _require(entry.get("status") == "decided", f"RETIRE {legacy} status != decided")
        else:
            raise ManifestError(f"decisão desconhecida em {legacy}: {decision}")

    _require(redirect_n == PINNED_REDIRECT_COUNT, f"REDIRECT ready={redirect_n}, pin={PINNED_REDIRECT_COUNT}")
    _require(retire_n == PINNED_RETIRE_COUNT, f"RETIRE={retire_n}, pin={PINNED_RETIRE_COUNT}")
    _require(hold_n == PINNED_HOLD_COUNT, f"HOLD={hold_n}, pin={PINNED_HOLD_COUNT}")
    _require(migrate_n == PINNED_MIGRATE_COUNT, f"MIGRATE={migrate_n}, pin={PINNED_MIGRATE_COUNT}")
    _require(ignore_n == PINNED_IGNORE_COUNT, f"IGNORE={ignore_n}, pin={PINNED_IGNORE_COUNT}")
    _require(legal_n == PINNED_LEGAL_COUNT, f"LEGAL={legal_n}, pin={PINNED_LEGAL_COUNT}")
    _require(len(persist_sets) == 1, "allowlists de query divergem entre REDIRECT ready")


def _assert_safe_target(target: str, legacy: str) -> None:
    _require(isinstance(target, str) and target, f"target vazio em {legacy}")
    _require("*" not in target, f"wildcard proibido no target de {legacy}: {target}")
    normalized = target.rstrip()
    _require(
        normalized not in FORBIDDEN_GENERIC_TARGETS,
        f"target genérico/inseguro recusado para {legacy}: {target}",
    )
    parts = urlsplit(target)
    _require(parts.scheme == "https", f"target deve ser https: {target}")
    _require(parts.hostname == TARGET_HOSTNAME, f"target host deve ser {TARGET_HOSTNAME}: {target}")
    path = parts.path or "/"
    _require(path not in FORBIDDEN_TARGET_PATHS, f"target path genérico recusado para {legacy}: {target}")
    _require(path not in {"", "/"}, f"target não pode ser a home CONFENGE: {target}")


def compile_execute_set(data: dict[str, Any], manifesto_sha256: str) -> CompiledMap:
    persist: tuple[str, ...] = ()
    rules: list[RedirectRule] = []
    holds: list[str] = []
    removal = ""
    for entry in data["entries"]:
        decision = entry["decision"]
        legacy_path = normalize_path(urlsplit(entry["legacy_url"]).path)
        if decision in HOLD_DECISIONS:
            holds.append(legacy_path)
            continue
        if decision not in REDIRECT_DECISIONS:
            continue
        qrule = entry["query_string_rule"]
        persist = tuple(qrule["persist"])
        removal = str(entry.get("removal_trigger") or removal)
        target = entry.get("target_url") or entry.get("target")
        canon = entry.get("expected_canonical") or entry.get("destination_canonical") or target
        rules.append(
            RedirectRule(
                path=legacy_path,
                target_url=target,
                expected_canonical=canon,
                family=str(entry.get("family") or "redirect"),
                owner=str(entry.get("bridge_owner") or BRIDGE_OWNER),
                persist=persist,
                expected_http=int(entry["expected_http"]),
            )
        )
    rules.sort(key=lambda r: r.path)
    holds = sorted(set(holds))
    _require(len(rules) == PINNED_REDIRECT_COUNT, "compile_execute_set: contagem != pin")
    _require(len(holds) == PINNED_HOLD_COUNT, "compile_execute_set: HOLD contagem != pin")
    by_path = {rule.path: rule for rule in rules}
    compiled = CompiledMap(
        manifesto_sha256=manifesto_sha256,
        config_sha256="",
        persist=persist,
        redirects=tuple(rules),
        by_path=by_path,
        holds=tuple(holds),
        default_status=DEFAULT_STATUS,
        observation_window_days=OBSERVATION_WINDOW_DAYS,
        owner=BRIDGE_OWNER,
        removal_trigger=removal,
        expiry_review=f"{OBSERVATION_WINDOW_DAYS} days after first production 301 of {manifesto_sha256}",
    )
    payload = _map_payload(compiled)
    digest = sha256_bytes(_canonical_json(payload))
    return CompiledMap(
        manifesto_sha256=compiled.manifesto_sha256,
        config_sha256=digest,
        persist=compiled.persist,
        redirects=compiled.redirects,
        by_path=compiled.by_path,
        holds=compiled.holds,
        default_status=compiled.default_status,
        observation_window_days=compiled.observation_window_days,
        owner=compiled.owner,
        removal_trigger=compiled.removal_trigger,
        expiry_review=compiled.expiry_review,
    )


def _map_payload(compiled: CompiledMap) -> dict[str, Any]:
    return {
        "manifesto_sha256": compiled.manifesto_sha256,
        "pinned_commit": PINNED_COMMIT,
        "default_status": compiled.default_status,
        "owner": compiled.owner,
        "observation_window_days": compiled.observation_window_days,
        "expiry_review": compiled.expiry_review,
        "removal_trigger": compiled.removal_trigger,
        "persist": list(compiled.persist),
        "holds": list(compiled.holds),
        "redirects": [
            {
                "path": rule.path,
                "target_url": rule.target_url,
                "expected_canonical": rule.expected_canonical,
                "family": rule.family,
                "owner": rule.owner,
                "persist": list(rule.persist),
                "expected_http": rule.expected_http,
            }
            for rule in compiled.redirects
        ],
    }


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def compiled_from_map_file(path: Path) -> CompiledMap:
    raw = path.read_bytes()
    data = json.loads(raw)
    rules = []
    for item in data["redirects"]:
        rules.append(
            RedirectRule(
                path=item["path"],
                target_url=item["target_url"],
                expected_canonical=item["expected_canonical"],
                family=item["family"],
                owner=item["owner"],
                persist=tuple(item["persist"]),
                expected_http=int(item["expected_http"]),
            )
        )
    by_path = {rule.path: rule for rule in rules}
    digest = data.get("config_sha256") or sha256_bytes(raw)
    return CompiledMap(
        manifesto_sha256=data["manifesto_sha256"],
        config_sha256=digest,
        persist=tuple(data.get("persist") or ()),
        redirects=tuple(rules),
        by_path=by_path,
        holds=tuple(data.get("holds") or ()),
        default_status=int(data.get("default_status") or DEFAULT_STATUS),
        observation_window_days=int(data.get("observation_window_days") or OBSERVATION_WINDOW_DAYS),
        owner=str(data.get("owner") or BRIDGE_OWNER),
        removal_trigger=str(data.get("removal_trigger") or ""),
        expiry_review=str(data.get("expiry_review") or ""),
    )


def empty_retire_map(manifesto_sha256: str = PINNED_SHA256) -> CompiledMap:
    """Pre-bridge state: default 410, zero 301s. Rollback target."""
    payload = {
        "manifesto_sha256": manifesto_sha256,
        "pinned_commit": PINNED_COMMIT,
        "default_status": DEFAULT_STATUS,
        "owner": BRIDGE_OWNER,
        "observation_window_days": OBSERVATION_WINDOW_DAYS,
        "expiry_review": "pre-bridge",
        "removal_trigger": "pre-bridge — no 301s active",
        "persist": [],
        "holds": [],
        "redirects": [],
    }
    digest = sha256_bytes(_canonical_json(payload))
    return CompiledMap(
        manifesto_sha256=manifesto_sha256,
        config_sha256=digest,
        persist=(),
        redirects=(),
        by_path={},
        default_status=DEFAULT_STATUS,
        observation_window_days=OBSERVATION_WINDOW_DAYS,
        owner=BRIDGE_OWNER,
        removal_trigger="pre-bridge — no 301s active",
        expiry_review="pre-bridge",
    )


_TERMINATOR_REQUIRED = (
    "smartlic.tech",
    "www.smartlic.tech",
    "http://smartlic.tech",
    "http://www.smartlic.tech",
    "reverse_proxy 127.0.0.1:8765",
    "auto_https disable_redirects",
    "{$SMARTLIC_ACME_EMAIL}",
    "request>uri regexp",
    "request>headers>User-Agent delete",
    "request>remote_ip delete",
    "request>client_ip delete",
    "tls {",
)
# Official Caddy `query` only mutates named keys. A bare `request>uri query`
# is a no-op and leaves email/cnpj/token in the terminator access log.
# Replace the query (and the '?') so the logged URI is path-only.
URI_QUERY_STRIP = 'request>uri regexp "\\?.*" ""'
_TERMINATOR_FORBIDDEN_PREFIX = "reverse_proxy 127.0.0.1:"
_TERMINATOR_FORBIDDEN_PORTS = ("8000", "3000")
_TERMINATOR_FORBIDDEN_KEYS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN CERTIFICATE",
)


def assert_terminator_safe(text: str) -> None:
    """Fail closed if the terminator is not apex+www ACME → local :8765."""
    for token in _TERMINATOR_REQUIRED:
        _require(token in text, f"Caddyfile incompleto: falta {token!r}")
    lowered = text.lower()
    for port in _TERMINATOR_FORBIDDEN_PORTS:
        token = _TERMINATOR_FORBIDDEN_PREFIX + port
        _require(token not in text, f"Caddyfile inseguro: {token}")
    for token in _TERMINATOR_FORBIDDEN_KEYS:
        _require(token.lower() not in lowered, f"Caddyfile inseguro: {token}")
    _require("redir /" not in lowered, "Caddyfile não pode redir /*")
    _require(
        URI_QUERY_STRIP in text,
        "Caddyfile deve stripar a query da URI (regexp \\?.* → vazio)",
    )
    _require(
        "request>headers>User-Agent delete" in text,
        "Caddyfile deve apagar User-Agent do log",
    )
    _require(
        "request>remote_ip delete" in text,
        "Caddyfile deve apagar remote_ip do log",
    )
    _require(
        "request>client_ip delete" in text,
        "Caddyfile deve apagar client_ip do log",
    )
    if "request>uri query" in text:
        raise ManifestError(
            "Caddyfile: `request>uri query` sem delete/replace/hash não remove PII; "
            "usar regexp que corta tudo após '?'"
        )


def render_caddyfile(compiled: CompiledMap) -> str:
    """Deployable TLS terminator. Never reverse_proxy to :8000/:3000.

    Caddy obtains and renews one Let's Encrypt certificate with SAN
    smartlic.tech + www.smartlic.tech. Private keys stay in the Caddy
    data dir on the host (typically /var/lib/caddy, mode 0700). HTTP is
    proxied, not redirected, so ready paths remain a single 301 hop.
    """
    lines = [
        "# Generated by bridge/generate.py — DO NOT EDIT.",
        f"# manifesto_sha256={compiled.manifesto_sha256}",
        f"# config_sha256={compiled.config_sha256}",
        f"# pinned_commit={PINNED_COMMIT}",
        "# Purpose: ACME TLS terminator + reverse_proxy to local serve.py :8765.",
        "# SAN: one certificate for smartlic.tech + www.smartlic.tech.",
        "# ACME: Let's Encrypt; email from $SMARTLIC_ACME_EMAIL (not a secret, not a key).",
        "# Renewal: Caddy renews automatically ~30 days before expiry.",
        "# Permissions: Caddy user owns the data dir (0700). No private keys in Git.",
        "# HTTP is proxied (auto_https disable_redirects) so ready paths stay one hop.",
        "# Forbidden: product application upstreams (:8000/:3000) and SaaS runtimes.",
        "# Live DNS apply is owner-only — see bridge/docs/CUTOVER.md.",
        "",
        "{",
        "	email {$SMARTLIC_ACME_EMAIL}",
        "	auto_https disable_redirects",
        "}",
        "",
        "(bridge_proxy) {",
        "	header {",
        '		Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        "		X-Content-Type-Options nosniff",
        "		Referrer-Policy no-referrer",
        f'		X-Bridge-Manifest-Hash "{compiled.manifesto_sha256}"',
        f'		X-Bridge-Config-Hash "{compiled.config_sha256}"',
        "	}",
        "	log {",
        "		output stdout",
        "		format filter {",
        "			wrap console",
        "			fields {",
        "				" + URI_QUERY_STRIP,
        "				request>headers>Cookie delete",
        "				request>headers>Authorization delete",
        "				request>headers>User-Agent delete",
        "				request>remote_ip delete",
        "				request>client_ip delete",
        "			}",
        "		}",
        "	}",
        "	reverse_proxy 127.0.0.1:8765",
        "}",
        "",
        "smartlic.tech, www.smartlic.tech {",
        "	tls {",
        "		protocols tls1.2 tls1.3",
        "	}",
        "	import bridge_proxy",
        "}",
        "",
        "http://smartlic.tech, http://www.smartlic.tech {",
        "	import bridge_proxy",
        "}",
        "",
    ]
    text = "\n".join(lines)
    assert_terminator_safe(text)
    return text


def render_rules_txt(compiled: CompiledMap) -> str:
    rows = [
        f"# manifesto={compiled.manifesto_sha256}",
        f"# config={compiled.config_sha256}",
        f"# default={compiled.default_status}",
        "legacy_path\ttarget_url\tstatus",
    ]
    for rule in compiled.redirects:
        rows.append(f"{rule.path}\t{rule.target_url}\t{rule.expected_http}")
    rows.append(f"*\t(none)\t{compiled.default_status}")
    return "\n".join(rows) + "\n"


def emit(compiled: CompiledMap, out_dir: Path = GENERATED_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = _map_payload(compiled)
    payload["config_sha256"] = compiled.config_sha256
    map_bytes = _canonical_json(payload)
    recomputed = sha256_bytes(_canonical_json(_map_payload(compiled)))
    if recomputed != compiled.config_sha256:
        raise ManifestError("config hash não é determinístico")
    (out_dir / "bridge-map.json").write_bytes(map_bytes)
    (out_dir / "Caddyfile").write_text(render_caddyfile(compiled), encoding="utf-8")
    (out_dir / "rules.txt").write_text(render_rules_txt(compiled), encoding="utf-8")
    (out_dir / "config.sha256").write_text(compiled.config_sha256 + "\n", encoding="utf-8")
    return out_dir / "bridge-map.json"


def load_and_compile(path: Path = MANIFEST_PATH) -> CompiledMap:
    raw = load_manifest_bytes(path)
    digest = assert_pinned_hash(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifesto JSON inválido: {exc}") from exc
    validate_schema(data)
    return compile_execute_set(data, digest)


def probe_targets(compiled: CompiledMap, timeout: float = 15.0) -> None:
    """Fail closed if any ready target is not HTTPS 200 on confenge.com.br."""
    import ssl
    import urllib.error
    import urllib.request

    ctx = ssl.create_default_context()
    errors: list[str] = []
    for rule in compiled.redirects:
        req = urllib.request.Request(
            rule.target_url,
            method="HEAD",
            headers={"User-Agent": "SmartLic-2115-bridge-probe/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                final = resp.geturl()
        except urllib.error.HTTPError as exc:
            errors.append(f"{rule.path} → {rule.target_url} HTTP {exc.code}")
            continue
        except Exception as exc:  # noqa: BLE001 — probe must surface any failure
            errors.append(f"{rule.path} → {rule.target_url} {type(exc).__name__}: {exc}")
            continue
        host = (urlsplit(final).hostname or "").lower()
        if status != 200:
            errors.append(f"{rule.path} → {rule.target_url} status={status}")
        if host != TARGET_HOSTNAME:
            errors.append(f"{rule.path} hop/host inesperado: {final}")
        if status == 200 and host == TARGET_HOSTNAME:
            print(f"PROBE_OK path={rule.path} target={rule.target_url} status={status}")
    if errors:
        raise ManifestError("destino ready indisponível:\n- " + "\n- ".join(errors))


def rollback(generated: Path = GENERATED_DIR) -> Path:
    previous = generated / "previous" / "bridge-map.json"
    current = generated / "bridge-map.json"
    if not previous.is_file():
        raise ManifestError(
            f"rollback recusado: {previous} ausente. "
            "Desbloqueio: manter generated/previous/bridge-map.json como última config conhecida."
        )
    compiled = compiled_from_map_file(previous)
    emit(compiled, generated)
    return current


def snapshot_previous(generated: Path = GENERATED_DIR) -> None:
    current = generated / "bridge-map.json"
    previous_dir = generated / "previous"
    previous_dir.mkdir(parents=True, exist_ok=True)
    if current.is_file():
        (previous_dir / "bridge-map.json").write_bytes(current.read_bytes())
        return
    emit(empty_retire_map(), previous_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and generate the #2115 redirect bridge.")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--out", type=Path, default=GENERATED_DIR)
    parser.add_argument("--check", action="store_true", help="validate + generate; compare to committed files")
    parser.add_argument("--probe-targets", action="store_true", help="require live 200 on each ready target")
    parser.add_argument("--rollback", action="store_true", help="restore generated/previous (one step)")
    parser.add_argument("--snapshot-previous", action="store_true", help="copy current map to previous/")
    parser.add_argument("--write-pre-bridge-previous", action="store_true", help="write 410-only previous map")
    args = parser.parse_args(argv)

    try:
        if args.rollback:
            path = rollback(args.out)
            print(f"ROLLBACK_OK {path}")
            return 0
        if args.write_pre_bridge_previous:
            emit(empty_retire_map(), args.out / "previous")
            print("PRE_BRIDGE_PREVIOUS_OK")
            return 0
        if args.snapshot_previous:
            snapshot_previous(args.out)
            print("SNAPSHOT_PREVIOUS_OK")
            return 0

        compiled = load_and_compile(args.manifest)
        if args.probe_targets:
            probe_targets(compiled)
        emit(compiled, args.out)
        assert_terminator_safe((args.out / "Caddyfile").read_text(encoding="utf-8"))
        if args.check:
            produced = (args.out / "bridge-map.json").read_bytes()
            written_hash = (args.out / "config.sha256").read_text(encoding="utf-8").strip()
            if written_hash != compiled.config_sha256:
                raise ManifestError("config.sha256 diverge do mapa gerado")
            committed = GENERATED_DIR / "bridge-map.json"
            if committed.is_file() and args.out.resolve() == GENERATED_DIR.resolve():
                if committed.read_bytes() != produced:
                    raise ManifestError("generated/bridge-map.json não é o output determinístico atual")
        print(
            "GENERATE_OK "
            f"manifesto={compiled.manifesto_sha256} "
            f"config={compiled.config_sha256} "
            f"redirects={len(compiled.redirects)} "
            f"default={compiled.default_status}"
        )
        return 0
    except ManifestError as exc:
        print(f"GENERATE_BLOCKED {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
