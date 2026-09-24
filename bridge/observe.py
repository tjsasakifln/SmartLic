#!/usr/bin/env python3
"""Privacy-safe window recorder for the temporary #2115 redirect bridge.

Post-resolve side effect only. Never feeds counts back into Decision.
Stdlib only. Not an analytics product. Loopback 301s are process-local
and must not be written as production first-production-301.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from bridge.pins import (
    MIN_ALLOWED_TRAFFIC_COUNT,
    OBSERVATION_WINDOW_DAYS,
    PINNED_CANONICAL_HOST,
)
from bridge.policy import Decision, normalize_path

RETENTION_DAYS = 35  # 28-day window + 7 days; then delete.
WINDOW_DAYS = OBSERVATION_WINDOW_DAYS
EXPORT_SCHEMA = "smartlic-2115-window-export-v1"
RECORD_KEYS = (
    "ts",
    "manifesto_sha256",
    "config_sha256",
    "action",
    "path_class",
    "status",
    "latency_ms",
)
# Optional non-PII diagnostics. Never query, IP, or UA.
OPTIONAL_RECORD_KEYS = ("hops", "critical_url")

_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Full or compressed IPv6 only — must not match ISO times like 20:00:00.
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b"
    r"|(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{0,4}"
    r"|(?:[0-9a-f]{1,4}:)*::[0-9a-f:]*",
    re.I,
)
_UA_RE = re.compile(r"Mozilla/\d|User-Agent", re.I)

PATH_CLASS_INTERNAL = "internal"
PATH_CLASS_LOGIN = "login"
PATH_CLASS_ROOT = "root"
PATH_CLASS_READY = "ready"
PATH_CLASS_HOLD = "hold"
PATH_CLASS_UNMAPPED = "unmapped"
PATH_CLASS_UNMAPPED_HOST = "unmapped-host"
PATH_CLASS_ERROR = "error"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def redact_query(_raw_query: str) -> str:
    """Query values never survive. Keys are dropped too."""
    return ""


def classify_path(path: str, decision: Decision) -> str:
    """Coarse class. Unknown visitor paths become unmapped — not stored raw."""
    if decision.family == "error" or decision.rule_id == "resolve-error":
        return PATH_CLASS_ERROR
    norm = normalize_path(path)
    if norm.startswith("/__bridge/"):
        return PATH_CLASS_INTERNAL
    if norm == "/login":
        return PATH_CLASS_LOGIN
    if norm == "/":
        return PATH_CLASS_ROOT
    if decision.family == "hold" or decision.rule_id == "hold-fail-closed":
        return PATH_CLASS_HOLD
    if decision.status == 301:
        return PATH_CLASS_READY
    if decision.rule_id == "unmapped-host":
        return PATH_CLASS_UNMAPPED_HOST
    return PATH_CLASS_UNMAPPED


def critical_url_for(path: str, path_class: str) -> str | None:
    """Known catalog / named paths only. Never an arbitrary visitor string."""
    if path_class == PATH_CLASS_READY:
        return normalize_path(path)
    if path_class in {PATH_CLASS_LOGIN, PATH_CLASS_ROOT, PATH_CLASS_HOLD}:
        if path_class == PATH_CLASS_HOLD:
            return PATH_CLASS_HOLD
        return normalize_path(path)
    return None


def assert_no_pii(text: str) -> None:
    """Fail closed if a serialized artifact would persist identifiers."""
    if _EMAIL_RE.search(text):
        raise ValueError("observe refused: email-like value")
    if _IPV4_RE.search(text):
        raise ValueError("observe refused: raw IPv4")
    if _IPV6_RE.search(text):
        raise ValueError("observe refused: raw IPv6")
    if _UA_RE.search(text):
        raise ValueError("observe refused: user-agent")


def make_record(
    *,
    manifesto_sha256: str,
    config_sha256: str,
    decision: Decision,
    path: str,
    latency_ms: float,
    ts: datetime | None = None,
    query: str = "",
    remote_ip: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """Build one structured record. Extra identity args are accepted and discarded."""
    del query, remote_ip, user_agent
    path_class = classify_path(path, decision)
    record: dict[str, Any] = {
        "ts": isoformat_z(ts or utc_now()),
        "manifesto_sha256": manifesto_sha256,
        "config_sha256": config_sha256,
        "action": decision.family,
        "path_class": path_class,
        "status": int(decision.status),
        "latency_ms": round(float(latency_ms), 3),
        "hops": int(decision.hops),
    }
    crit = critical_url_for(path, path_class)
    if crit is not None:
        record["critical_url"] = crit
    serialized = serialize_record(record)
    assert_no_pii(serialized)
    return record


def serialize_record(record: Mapping[str, Any]) -> str:
    allowed = set(RECORD_KEYS) | set(OPTIONAL_RECORD_KEYS)
    payload = {key: record[key] for key in RECORD_KEYS}
    for key in OPTIONAL_RECORD_KEYS:
        if key in record and record[key] is not None:
            payload[key] = record[key]
    extra = set(record) - allowed
    if extra:
        # Drop anything unexpected rather than persist it.
        pass
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def target_health_from_results(results: Iterable[Mapping[str, Any]] | None) -> dict[str, Any]:
    rows = list(results or ())
    if not rows:
        return {"status": "UNOBSERVED", "checked": 0, "failing": 0}
    failing = 0
    for row in rows:
        status = row.get("status")
        error = row.get("error")
        if error or status != 200:
            failing += 1
    return {
        "status": "FAIL" if failing else "OK",
        "checked": len(rows),
        "failing": failing,
    }


def evaluate_signals(
    summary: Mapping[str, Any],
    *,
    production_first_301: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Removal/rollback evaluators. Loopback first-301 does not start the window."""
    counts = summary.get("counts") or {}
    unexpected_404 = int(counts.get("404") or 0)
    errors = int(counts.get("errors") or 0)
    status_5xx = int(counts.get("5xx") or 0)
    chain_gt1 = int(counts.get("chain_gt1") or 0)
    loop_count = int(counts.get("loop") or 0)
    target_status = str((summary.get("target_health") or {}).get("status") or "UNOBSERVED")
    target_fail = target_status == "FAIL"
    residual_priority = (
        unexpected_404 > 0
        or status_5xx > 0
        or errors > 0
        or chain_gt1 > 0
        or loop_count > 0
    )

    prod = production_first_301 or {}
    config_hash = str(summary.get("config_sha256") or "")
    window_started = (
        str(prod.get("status") or "") == "OBSERVED"
        and str(prod.get("config_sha256") or "") == config_hash
        and bool(config_hash)
    )
    window_elapsed = False
    observation_days_elapsed = 0
    started_raw = prod.get("observation_started_at") or prod.get("captured_at")
    if window_started and started_raw:
        try:
            started = datetime.fromisoformat(str(started_raw).replace("Z", "+00:00"))
            moment = now or utc_now()
            delta = moment - started
            observation_days_elapsed = max(0, int(delta.days))
            window_elapsed = moment >= started + timedelta(days=WINDOW_DAYS)
        except ValueError:
            window_elapsed = False
            observation_days_elapsed = 0

    traffic_count = int(counts.get("301") or 0)
    if window_started:
        # The authorizing production 301 itself satisfies the minimum.
        traffic_count = max(traffic_count, MIN_ALLOWED_TRAFFIC_COUNT)
    min_allowed = MIN_ALLOWED_TRAFFIC_COUNT

    rollback = residual_priority or target_fail
    if not window_started:
        removal = "HOLD_WINDOW_NOT_STARTED"
    elif residual_priority or target_fail:
        removal = "HOLD_RESIDUAL"
    elif not window_elapsed or traffic_count < min_allowed:
        removal = "WAIT_WINDOW"
    else:
        removal = "READY_FOR_REVIEW"

    return {
        "window_started": window_started,
        "window_elapsed": window_elapsed,
        "observation_days_elapsed": observation_days_elapsed,
        "min_allowed_traffic_count": min_allowed,
        "traffic_count": traffic_count,
        "residual_priority": residual_priority,
        "unexpected_404": unexpected_404,
        "errors": errors,
        "status_5xx": status_5xx,
        "chain_gt1": chain_gt1,
        "chain": chain_gt1 > 0,
        "loop": loop_count > 0,
        "target": PINNED_CANONICAL_HOST,
        "target_health_fail": target_fail,
        "rollback": rollback,
        "removal": removal,
        "first_301_scope": "production" if window_started else "process-local",
    }


def observation_exit_fields(
    signals: Mapping[str, Any],
    *,
    production_first_301: Mapping[str, Any] | None = None,
    removal_trigger: str = "",
    config_sha256: str = "",
) -> dict[str, Any]:
    """Stable observation/exit record. Does not start the window."""
    prod = production_first_301 or {}
    started = prod.get("observation_started_at") or prod.get("captured_at")
    http_status = prod.get("http_status")
    if http_status is None:
        raw_status = prod.get("status")
        http_status = raw_status if isinstance(raw_status, int) else None
    return {
        "config_sha256": config_sha256 or str(prod.get("config_sha256") or ""),
        "first_production_301_timestamp": started if signals.get("window_started") else None,
        "http_status": http_status if signals.get("window_started") else None,
        "chain": bool(signals.get("chain")),
        "loop": bool(signals.get("loop")),
        "target": str(signals.get("target") or PINNED_CANONICAL_HOST),
        "min_allowed_traffic_count": int(
            signals.get("min_allowed_traffic_count") or MIN_ALLOWED_TRAFFIC_COUNT
        ),
        "traffic_count": int(signals.get("traffic_count") or 0),
        "observation_days_elapsed": int(signals.get("observation_days_elapsed") or 0),
        "removal": str(signals.get("removal") or "HOLD_WINDOW_NOT_STARTED"),
        "removal_trigger": removal_trigger,
    }


def build_export(
    summary: Mapping[str, Any],
    *,
    production_first_301: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    signals = evaluate_signals(
        summary, production_first_301=production_first_301, now=now
    )
    first = summary.get("first_301") or {}
    payload = {
        "schema": EXPORT_SCHEMA,
        "campaign": "SMARTLIC-004",
        "manifesto_sha256": summary.get("manifesto_sha256"),
        "config_sha256": summary.get("config_sha256"),
        "first_301_at": first.get("at"),
        "first_301_config_sha256": first.get("config_sha256"),
        "first_301_scope": signals["first_301_scope"],
        "first_production_301": (
            "OBSERVED" if signals["window_started"] else "UNOBSERVED"
        ),
        "counts": dict(summary.get("counts") or {}),
        "by_family": dict(summary.get("by_family") or {}),
        "by_path_class": dict(summary.get("by_path_class") or {}),
        "by_critical_url": dict(summary.get("by_critical_url") or {}),
        "target_health": dict(summary.get("target_health") or {"status": "UNOBSERVED"}),
        "signals": signals,
        "retention_days": RETENTION_DAYS,
        "retention_policy": "28+7 then delete; not a warehouse",
    }
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert_no_pii(text)
    return payload


def write_export(path: Path, export: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(export, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert_no_pii(body)
    path.write_text(body, encoding="utf-8")


@dataclass
class WindowRecorder:
    manifesto_sha256: str
    config_sha256: str
    clock: Callable[[], datetime] | None = None
    target_health: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._status = Counter()
        self._family = Counter()
        self._path_class = Counter()
        self._critical = Counter()
        self._errors = 0
        self._chain_gt1 = 0
        self._first_301_at: str | None = None
        self._first_301_config: str | None = None
        self._first_301_manifesto: str | None = None
        self._clock = self.clock or utc_now
        if self.target_health is None:
            self.target_health = target_health_from_results(None)

    def record(
        self,
        decision: Decision,
        *,
        path: str,
        latency_ms: float,
        query: str = "",
        remote_ip: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        item = make_record(
            manifesto_sha256=self.manifesto_sha256,
            config_sha256=self.config_sha256,
            decision=decision,
            path=path,
            latency_ms=latency_ms,
            ts=self._clock(),
            query=query,
            remote_ip=remote_ip,
            user_agent=user_agent,
        )
        with self._lock:
            self._ingest(item)
        return item

    def record_error(self, *, latency_ms: float, path: str = "/") -> dict[str, Any]:
        decision = Decision(
            status=500,
            location=None,
            rule_id="resolve-error",
            family="error",
            hops=0,
        )
        return self.record(decision, path=path, latency_ms=latency_ms)

    def note_error(self) -> None:
        with self._lock:
            self._errors += 1

    def set_target_health(self, health: Mapping[str, Any]) -> None:
        with self._lock:
            self.target_health = dict(health)

    def _ingest(self, item: Mapping[str, Any]) -> None:
        status = int(item["status"])
        self._status[status] += 1
        self._family[str(item["action"])] += 1
        self._path_class[str(item["path_class"])] += 1
        crit = item.get("critical_url")
        if crit:
            self._critical[str(crit)] += 1
        if status >= 500 or str(item["action"]) == "error":
            self._errors += 1
        if int(item.get("hops") or 0) > 1:
            self._chain_gt1 += 1
        if status == 301 and self._first_301_at is None:
            self._first_301_at = str(item["ts"])
            self._first_301_config = str(item["config_sha256"])
            self._first_301_manifesto = str(item["manifesto_sha256"])

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "manifesto_sha256": self.manifesto_sha256,
                "config_sha256": self.config_sha256,
                "first_301": {
                    "at": self._first_301_at,
                    "config_sha256": self._first_301_config,
                    "manifesto_sha256": self._first_301_manifesto,
                    "scope": "process-local",
                },
                "counts": {
                    "301": int(self._status.get(301, 0)),
                    "410": int(self._status.get(410, 0)),
                    "404": int(self._status.get(404, 0)),
                    "5xx": int(sum(v for k, v in self._status.items() if k >= 500)),
                    "errors": int(self._errors),
                    "chain_gt1": int(self._chain_gt1),
                    "total": int(sum(self._status.values())),
                },
                "by_family": dict(sorted(self._family.items())),
                "by_path_class": dict(sorted(self._path_class.items())),
                "by_critical_url": dict(sorted(self._critical.items())),
                "target_health": dict(self.target_health or target_health_from_results(None)),
                "retention_days": RETENTION_DAYS,
                "retention_policy": "28+7 then delete; not a warehouse",
            }

    def export(
        self,
        *,
        production_first_301: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_export(self.summary(), production_first_301=production_first_301)


def records_from_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        assert_no_pii(line)
        items.append(json.loads(line))
    return items


def recorder_from_records(
    records: Iterable[Mapping[str, Any]],
    *,
    manifesto_sha256: str,
    config_sha256: str,
    target_health: Mapping[str, Any] | None = None,
) -> WindowRecorder:
    rec = WindowRecorder(
        manifesto_sha256=manifesto_sha256,
        config_sha256=config_sha256,
        target_health=dict(target_health) if target_health else None,
    )
    for item in records:
        assert_no_pii(serialize_record(item))
        rec._ingest(dict(item))  # noqa: SLF001 — rebuild from persisted JSONL
    return rec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize/export #2115 window records. No PII. Not production first-301."
    )
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--target-health", type=Path, default=None)
    parser.add_argument("--first-production", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.records.is_file():
        print(f"OBSERVE_BLOCKED field=records action=write JSONL via serve --records-file", file=sys.stderr)
        return 2

    rows = records_from_jsonl(args.records)
    if not rows:
        print("OBSERVE_BLOCKED field=records action=capture at least one structured record", file=sys.stderr)
        return 2

    manifesto = str(rows[0].get("manifesto_sha256") or "")
    config = str(rows[0].get("config_sha256") or "")
    health = None
    if args.target_health is not None:
        health = json.loads(args.target_health.read_text(encoding="utf-8"))
    rec = recorder_from_records(
        rows,
        manifesto_sha256=manifesto,
        config_sha256=config,
        target_health=health,
    )
    production = None
    if args.first_production is not None and args.first_production.is_file():
        production = json.loads(args.first_production.read_text(encoding="utf-8"))
    export = rec.export(production_first_301=production)
    write_export(args.export, export)
    print(
        "OBSERVE_OK "
        f"schema={EXPORT_SCHEMA} "
        f"config={config} "
        f"first_301_at={export.get('first_301_at')} "
        f"scope={export.get('first_301_scope')} "
        f"removal={export['signals']['removal']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
