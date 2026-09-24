# SMARTLIC-LIVE-CUTOVER-EXECUTION-02

Status: `BLOCKED_SINGLE_EXTERNAL_ACTION`

Not `CUTOVER_READY`. Not `SMARTLIC_RESTORED`. Not `PRODUCT_LIVE`.
Empty apex/www DNS is the cutover start state, not a RETIRE of the 11-row map.
Observation window not started. #2115 and #2111 remain OPEN.

Safety: `bridge.apply` refuses extra-cli/warmbly `159.195.18.88` and refuses
to mutate Cloudflare zone `confenge.com.br`. Those are not the residual.

## Pins (origin/main includes #2151 `df9141d3`)

- manifesto `9e5667c127fc5494f5849aece2234b13a1c1db10257a17274545019634506ca9`
- config `fd391e3667541953e6a830135c863f75452a27c879308fd0012d517740e537a4`
- inventory commit `8a2f4d5bce7e23d0308246ed45ed4d58752984ac`

`python3 -m bridge.generate --check` = `GENERATE_OK` redirects=11 default=410.
`python3 -m unittest discover -s bridge/tests` = OK.
Eleven CONFENGE destinations HTTPS 200 via shipped `probe_targets`.

## Live names (start state)

| Name | Now |
|---|---|
| `smartlic.tech` | no A (degraded/empty; cutover start) |
| `www.smartlic.tech` | NXDOMAIN |
| `api.smartlic.tech` | NXDOMAIN (must not be revived as an API) |
| `confenge.com.br` | live Netlify HTTPS 200 |
| `api.confenge.com.br` | `159.195.18.88` (refused as bridge IPv4) |

Authorized extra-cli CF token sees only `confenge.com.br` (0 zones named
`smartlic.tech`). That token must not be exported into apply.

Provision claim recheck (authorized routes only): still false. Vault has
confenge.com.br CF/Netlify/GSC only. extra-cli SSH is `159.195.18.88` with
no `/etc/smartlic-bridge`. This WSL laptop (`177.132.192.183`) is residential
NAT, not the isolated bridge host.

## Apply

`python3 -m bridge.apply` → `BLOCKED_SINGLE_EXTERNAL_ACTION` / `applied=false`
while `BRIDGE_PUBLIC_IPV4`, `SMARTLIC_ACME_EMAIL`, `CF_API_TOKEN`, `CF_ZONE_ID`
(for zone **smartlic.tech**) are absent.

Empty DNS + isolated IPv4 + smartlic.tech zone creds → `READY_TO_APPLY` and a
non-empty apex/www DNS plan.

## Single residual human action

Write `/etc/smartlic-bridge/env` (mode 0640) on an **isolated** public IPv4 host
that is **not** `159.195.18.88`, with `BRIDGE_PUBLIC_IPV4=<that isolated IPv4>`
and `SMARTLIC_ACME_EMAIL=<ops contact>`, export `CF_API_TOKEN` and `CF_ZONE_ID`
for zone **smartlic.tech** (never `confenge.com.br`) in the apply shell, then
re-run `python3 -m bridge.apply`.
