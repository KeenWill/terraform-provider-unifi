# Network 11 legacy contract fixtures

`network11/` contains **synthetic** responses created 2026-11-02. None were captured
from Will's controller or a Network 11 lab. Network 11.0.97/99 and OS 6 are target
contracts, not observed versions; gateway model and firmware are not observed.

- `configured-users.json`: GET `/proxy/network/api/s/default/rest/user` and
  `/rest/user/{id}`. The numeric-string `dev_id_override` models the reported
  Network 11 type change ([upstream SDK patch](https://github.com/simplerick0/go-unifi/pull/1)).
  IDs/MACs/addresses/name/DNS are invented; references are consistent.
- `observed-user.json`: GET `/proxy/network/api/s/default/stat/user/{mac}`. Its
  observation ID deliberately differs from the configured reservation ID.
- `empty-statistics.json`: GET `/stat/user/{mac}` without telemetry, also reused
  as an empty configured collection for identity-migration failure tests.

These are independently authored field contracts against the pinned go-unifi
1.9.3 models and the Network 11 research, not copied upstream implementation.
Network 11 release notes confirm statistics reset, but do not specify these
legacy wire contracts; real controller confirmation is still required.
Tests also cover null/number/empty/string fingerprint values, decode errors,
authorization failures, ambiguous MACs and scoped lookups. No credentials,
cookies, captures or raw error bodies are embedded here.

The first slice's sanitized historical device recordings and Network 11 overlays
are replayed separately under `internal/provider/device/testdata/`, retaining
that source's MIT notice and explicit distinction between recorded and synthetic.

## Narrow security settings fixture

`security-settings.json` was independently authored on 2026-11-02 against the
pinned filipowm/go-unifi 1.9.3 `setting.go`, `setting_ips.generated.go` and
`setting_teleport.generated.go` contracts (MPL-2.0, already a dependency).
GET `/proxy/network/api/s/default/get/setting` returns both singleton objects;
PUT `/proxy/network/api/s/default/set/setting/{ips,teleport}` receives the selected
configuration snapshot with exactly one changed field.

This is **synthetic, not recorded**: Network/OS/model/firmware and capture date
are unobserved. IDs, four networks, 35 category names, subnet, suppression and
future fields are invented. There are no credentials or cookies. Tests preserve
all unowned values byte-for-byte at the JSON-field level and reject absent,
duplicate, malformed, authorization-failed and identity-mismatched snapshots.
The settings fixture must not be used as evidence of hardware compatibility.
