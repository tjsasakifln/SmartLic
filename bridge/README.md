# Redirect bridge (SmartLic#2115)

Isolated surface. Executes only the hash-pinned execute set from [web-cfg#62](https://github.com/tjsasakifln/web-cfg/issues/62).

| Pin | Value |
|---|---|
| Manifesto SHA-256 | `9e5667c127fc5494f5849aece2234b13a1c1db10257a17274545019634506ca9` |
| web-cfg commit (map pin) | `8a2f4d5bce7e23d0308246ed45ed4d58752984ac` |
| web-cfg counterpart | **MERGED** PR #97 (`bcc3fd6e`) on web-cfg **main** |
| Config hash | `fd391e3667541953e6a830135c863f75452a27c879308fd0012d517740e537a4` |
| Supersedes | `3c5a5b7aeb173a16cfb65c0314827d9022ba1b387901d1718e4fdfcbd0363023` / `78b7ebb9` (payment-delay remapped; not mixed) |
| Rules | 11 URL-specific 301s + 54 HOLD fail-closed + default 410 |
| Owner | SmartLic#2115 |
| Cost | UNKNOWN |
| Expiry | 28 days after the first production 301 of this hash |
| Removal trigger | window complete + zero residual priority errors + #2111 archive gate |
| Live DNS/TLS cutover | engineering **PIN_SYNCED_CUTOVER_READY**; live apply **BLOCKED** (`docs/CUTOVER_READINESS.md`) |

```text
python3 -m bridge.generate
python3 -m unittest discover -s bridge/tests -v
python3 -m bridge.serve --host 127.0.0.1 --port 8765
python3 -m bridge.observe --records window.jsonl --export window-export.json
python3 -m bridge.preflight && python3 -m bridge.apply --attach-live-transport
python3 -m bridge.monitor --out window-daily.json
```

Owner one-shot (no code edit): `docs/campaigns/CONFENGE-SMARTLIC-EQUITY-BRIDGE-CLOSEOUT-01/OPERATOR_ONE_SHOT.txt`.

Docs: `docs/CUTOVER.md`, `docs/CUTOVER_READINESS.md`, `docs/RUNBOOK.md`, `docs/ROLLBACK.md`, `docs/OBSERVABILITY.md`.
