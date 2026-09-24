"""Invariants of the hash-pinned web-cfg#62 / PR #97 execute set.

These constants describe SHA-256
``9e5667c127fc5494f5849aece2234b13a1c1db10257a17274545019634506ca9``.
A different inventory file must fail closed before any artifact is emitted.
"""

from __future__ import annotations

PINNED_SHA256 = "9e5667c127fc5494f5849aece2234b13a1c1db10257a17274545019634506ca9"
# SHA-256 of the canonical map payload (not the on-disk file, which also stores this digest).
# Computed by `python3 -m bridge.generate` after consuming web-cfg main (WEB-017 / #97 merged).
PINNED_CONFIG_SHA256 = "fd391e3667541953e6a830135c863f75452a27c879308fd0012d517740e537a4"
# Last commit that touched inventory.v2.json; now on web-cfg main via merge bcc3fd6e (#97).
PINNED_COMMIT = "8a2f4d5bce7e23d0308246ed45ed4d58752984ac"
# Historical v1 pin (same 11 ready 301s except later remaps). Docs only.
CITED_MANIFESTO_COMMIT = "dad3414c7a0073d0c1860d19704cff7e2a6e3b24"
# Immediate predecessor consume (v2 before payment-delay remap).
SUPERSEDED_SHA256 = "3c5a5b7aeb173a16cfb65c0314827d9022ba1b387901d1718e4fdfcbd0363023"
SUPERSEDED_V1_SHA256 = "c2cee8362321099205b76b11f89485d4248a00b8abbbda354d15964f6b316e0d"
SUPERSEDED_COMMIT = "78b7ebb9f8c26b754e5571248d014be305fbcf40"
COUNTERPART_HEAD = "8a2f4d5bce7e23d0308246ed45ed4d58752984ac"
COUNTERPART_MERGE_COMMIT = "bcc3fd6e19baf495962abd6c8edf33a2cb3304c7"
COUNTERPART_PR_STATE = "MERGED"
COUNTERPART_MERGED_AT = "2026-08-16T23:20:14Z"
PINNED_VERSION = "v2"
PINNED_SCHEMA = "smartlic-url-map-v2"
PINNED_REDIRECT_COUNT = 11
PINNED_RETIRE_COUNT = 1190
PINNED_HOLD_COUNT = 54
PINNED_MIGRATE_COUNT = 0
PINNED_IGNORE_COUNT = 0
PINNED_LEGAL_COUNT = 0
PINNED_CANONICAL_HOST = "https://confenge.com.br"
PINNED_LEGACY_HOST = "https://smartlic.tech"
PINNED_SOURCE = (
    "https://raw.githubusercontent.com/tjsasakifln/web-cfg/"
    f"{PINNED_COMMIT}/data/migrations/smartlic-url-map/inventory.v2.json"
)

LEGACY_HOSTNAMES = frozenset({"smartlic.tech", "www.smartlic.tech"})
TARGET_HOSTNAME = "confenge.com.br"
FORBIDDEN_TARGET_PATHS = frozenset({"/", "/consultoria-b2g", "/consultoria-b2g/"})
FORBIDDEN_GENERIC_TARGETS = frozenset(
    {
        "https://confenge.com.br/",
        "https://confenge.com.br",
        "https://confenge.com.br/consultoria-b2g/",
        "https://confenge.com.br/consultoria-b2g",
        "https://www.confenge.com.br/",
        "https://www.confenge.com.br",
    }
)

PII_QUERY_KEYS = frozenset(
    {
        "email",
        "phone",
        "name",
        "cnpj",
        "cpf",
        "telefone",
        "nome",
        "password",
        "token",
        "secret",
    }
)

DEFAULT_STATUS = 410
REDIRECT_STATUS = 301
OBSERVATION_WINDOW_DAYS = 28
# Exit cannot fire on zero production 301s of this hash (the first live 301 counts as 1).
MIN_ALLOWED_TRAFFIC_COUNT = 1
BRIDGE_OWNER = "SmartLic#2115"
COST = "UNKNOWN"

REDIRECT_DECISIONS = frozenset({"REDIRECT_301", "REDIRECT", "MIGRATE"})
FAIL_CLOSED_DECISIONS = frozenset(
    {
        "RETIRE_410",
        "RETIRE",
        "HOLD_TARGET_NOT_READY",
        "IGNORE_NONCANONICAL",
        "LEGAL_SECURITY_HOLD",
    }
)
HOLD_DECISIONS = frozenset({"HOLD_TARGET_NOT_READY"})
