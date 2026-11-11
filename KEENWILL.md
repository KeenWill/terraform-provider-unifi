# KeenWill UniFi provider: development baseline

This repository now contains the previously developed provider baseline.
It is **unreleased** and is not a published replacement for filipowm 1.1.0.
This synchronization does not change the registry identity or create a release.

## Provenance and boundaries

- Base: filipowm `v1.1.0`, dereferenced commit
  `00cf727bee7486f8e7dbf3ebb4dd2a4ae46e8d82` (annotated tag object
  `8f07cba6c5f212b47bc6ac6f5b943b8e6ac957b5`). Go 1.25.11 and go-unifi 1.9.3.
- Ported mono commits: `a4df72c5a747b2169393965722149c25f03640b5`
  (management network and address block),
  `f4c00ef3022c62c0ddebc3ea01f9a156df46b263` (only construct changed ports), and
  `51ab2006db6156d59fb77749a28384cdaba012db` (partial PUT omitting unchanged ports).
  The old custom network-zone mapping is superseded by upstream 1.1.0.
- MPL-2.0 is retained. The historical public aiounifi recordings have their MIT
  notice and explicit provenance in `internal/provider/device/testdata/`.
  They are not Network 11 or Beast compatibility certification.
- `internal/client/legacy` owns partial device transport and raw port preservation.
  `internal/client/integration` reserves the separate official API boundary;
  no official backend, implicit fallback, identity migration or SQL access exists
  in this slice. Other resources retain upstream's legacy SDK adapters.
- Go module/import paths and the Terraform source address remain upstream-shaped
  for compatibility during development. No registry identity migration occurs.

## Device behavior

The existing `mgmt_network_id` attribute and single-element `config_network`
list/block remain, including all seven fields (`type`, `ip`, `netmask`, `gateway`,
`dns1`, `dns2`, `dnssuffix`). Empty optional addresses are accepted for DHCP and
optional DNS; explicit empty management values reach the wire.

Management-only updates omit `port_overrides`. Changed ports merge raw controller
fields by port number and preserve fields not modeled by the provider/SDK for
retained ports. Omitted VLAN exclusions retain the freshly read snapshot even
on first management by MAC; only explicitly configured exclusions are written.
The configured array still owns membership: ports omitted from
an explicitly changed list lose their overrides. Omitting `port_override` now
preserves existing overrides; `port_override = []` deliberately sends `[]`.

Port set hashing includes configurable fields, so renames and other edits are
not lost. Planning carries omitted computed VLAN fields forward by port number,
avoiding perpetual diffs when a controller supplies defaults. Duplicate port
numbers are rejected when configuration is known. Existing SDK state retains its
resource type, ID, management block shape and import format; no ForceNew was added.

Radio/Etherlighting merge behavior, aggregation translation and successful empty
PUT response rereads remain. Explicit switch-VLAN false is serialized rather
than silently suppressed. A per-client device mutex covers read/merge/write;
separate provider processes still need operational exclusion. These are payload
contracts tested offline, not claims about hardware provisioning or reachability.

## Development wiring

Mono's `tofu-with-local-unifi-provider.sh` always builds this source, writes an
invocation-private override/config in a temporary directory, and cleans it up.
Missing Go fails; stale binaries are never reused. It accepts `TF_PROJECT_ROOT`
for disposable roots and never fetches credentials. `tf-op` on the devbox remains
the credential-resolving entrypoint for a later authorized live session.

The root pins upstream `filipowm/unifi = 1.1.0` and now tracks its regenerated
lockfile. **Those checksums identify registry artifacts, not this custom binary.**
The wrapper's override is essential for the development slice. Bare registry
1.1.0 still lacks the management fields. The wrapper is a temporary development
bridge; normal release use must install the signed KeenWill artifact and remove
the override. The imported upstream release workflows are not enabled or run by
this mono change; no release/tag has been created.

## Local evidence (2026-11-02)

All provider execution was isolated in a Linux network namespace with loopback
only, without credentials. Dependencies were cached before isolation.

- `go test ./...`, `go vet ./...`, and race tests for device, firewall and client
  packages pass. The controller acceptance package now gates at TestMain when
  `TF_ACC` is absent, before tests can access an uninitialized controller client.
  No controller acceptance tests were run.
- VPN cross-field validation defers unknown purpose/type values until planning
  can evaluate them; known missing/invalid combinations still fail.
- Wire regressions replay sanitized AP/switch recordings and synthetic overlays:
  all management fields, unchanged ports, edit/clear distinction, unknown port
  fields, malformed input rejection, empty PUT reread, radio/Etherlighting,
  switch-VLAN false, initial-management exclusion preservation versus explicit
  clear, import identity/management readback, computed defaults/no-op diffs and
  device locking.
- OpenTofu 1.12.5: the fixture runner validates/plans both mono device declarations
  and zone-policy ordering through the built provider. Its HTTPS server accepts
  only allowlisted GETs and fails the test on writes/unexpected paths.
- With PR 909 at `78c9f06a77b0e026120b8cda955ed921f8cdac80`, that fixture plan
  checks its 14 policies (`13 + N`, N=1), four order resources and one address
  group. Including baseline fixtures: **23 creates, zero changes/deletes** in
  disposable empty state. All policies are disabled and the address group is
  exactly `192.0.2.0/24`. This is not a production change count.
- Seven PR 909 mocked cases pass in scratch space. To obey the no-apply limit,
  the final ordering case was converted from mock apply to plan and checks four
  lists of length 3/3/3/5; six original plan cases were unchanged. It does not
  claim the original apply-time ID-order assertion ran. Ordering unit
  tests separately check ordering reconstruction, payload and unmanaged IDs.
- A scratch copy of the full infrastructure root, overlaid with those PR 909
  files, passes `tofu validate` with the custom provider. Its backend block and
  tfvars were removed; initialization used `-backend=false`. Only this scratch
  root was initialized, and it was never planned against live state.
- Unsigned development binaries cross-build with CGO disabled for Linux and macOS,
  amd64 and arm64. SHA256 receipts are local; no ZIP, signature, tag or release
  was published. Only the native Linux binary was executed.
- Device documentation was generated from the actual local provider schema.
  Shellcheck, shfmt, Ruff, Pyright, Nix formatting and diff whitespace checks pass.

Run instructions are in `infrastructure/terraform/tests/unifi-provider/README.md`
at the mono root. Local receipts and unsigned development binaries are under
`/tmp/unifi-own-provider/` on the build host. Terraform CLI and hardware acceptance
are not claimed. Existing upstream network/WLAN update risks and Network 11
ID/type migrations remain outside this device/ordering slice.

## Release and first live-plan handoff

No live controller requests, production-state plans, imports, applies, releases,
state migrations or merges are authorized or performed by this implementation.
GitHub-hosted Actions are intentionally unused (ticket 148); local gates are the
PR evidence. The separate `trusted`-runner PR plan workflow is skipped when the
PR has the `offline-validation-only` label. This PR carries that label; its
initially queued plan run was cancelled before execution.

For a release, Will must authorize the distinct source/distribution identity
(e.g. `KeenWill/unifi` or a checksum-pinned mirror), version such as `0.1.0-rc.1`,
and access to signing/registry credentials through the approved secret workflow.
Export this exact reviewed subtree to KeenWill/terraform-provider-unifi, retain
licenses, build platform ZIPs, sign SHA256 sums, attach source provenance/SBOM,
and verify installation/schema from those artifacts. Do not retag a release.
Then update every root/module source and lock entry to the actual published
artifact and remove normal-use overrides. No custom checksum may be fabricated
in the upstream lock entry.

For the first live plan, Will needs a separately approved devbox session using
**tf-op**, with working backend authorization and the appropriate UniFi API
credential injected there. Never run the historical import helper as a probe.
Confirm actual OS/Network versions and a suitable disposable-controller test;
fixture success alone does not establish Network 11 write safety. Prepare an
encrypted state backup, controller backup and explicit device/firewall rollback.
A source-address change needs reviewed `state replace-provider` after backup;
it does not translate IDs or resource schemas. Review a full-root plan for zero
unintended device/network/route/profile changes or replacements, verify zone
membership and policy ordering, and keep policies disabled. Activation, live
reachability checks and any apply require separate approval. Expired backend
access remains Will's live-session prerequisite, not a reason to run a live plan
from this lane.

## Second slice: official discovery client

`internal/client/integration` now supplies local HTTPS/API-key application info,
site mapping, device/radio inventory and firewall-policy discovery alongside the
legacy adapters. Construction performs no requests. Existing resource schemas,
backends and IDs are unchanged. No official write or automatic fallback is
introduced: partial discovery models are not safe replacement write payloads.
The client rejects redirects, bounds deadlines/body size/pagination, retries only
transient GET responses, and excludes response bodies and transport URLs from
errors. Custom transports support the existing explicit insecure option/custom
trust; default TLS validation remains enabled.

Network 11 fields include optional flow-reporting state, transmit-power mode and
802.11ah radio inventory. Nil distinguishes fields absent on older API versions
from explicit false/empty. Site mapping uses `internalReference`, not display
name, and rejects ambiguous mappings. Official IDs have distinct Go types from
legacy site references; no format-based ID conversion occurs.

Live vendor sources re-read on 2026-11-02:

- [Network 11.0.97](https://community.ui.com/releases/UniFi-Network-Application-11-0-97/15662d06-8122-44e2-a1ba-af5d71b8a045)
  and [11.0.99](https://community.ui.com/releases/UniFi-Network-Application-11-0-99/e166b2d2-e321-4e74-8efb-bfce33d6653c)
  via the public Network RSS: PostgreSQL/statistics/ZBF migration and OS 6 minimum;
  .99 improves migration reliability. Live flows/external lists need OS 6.0.10+.
- Dream Machines [6.0.7](https://community.ui.com/releases/UniFi-OS-Dream-Machines-6-0-7/439a4756-3fa0-4529-ba89-719ae900c752),
  [6.0.10](https://community.ui.com/releases/UniFi-OS-Dream-Machines-6-0-10/410d248a-2afb-4cee-a26f-79cb4bcf7ca0),
  [6.0.13](https://community.ui.com/releases/UniFi-OS-Dream-Machines-6-0-13/a59c938f-b7e7-4189-b00f-b6ac036dae2f)
  via public `community.svc.ui.com` release queries: Trixie, backup/session changes,
  DHCP/DNS/VPN fixes. These records carry the beta audience tag and no public
  product tag; .13 is not claimed to be the newest Beast build. .10/.13 bundle
  Network 10.6.106, so OS 6 alone does not establish Network 11 compatibility.
- Live [10.6.106](https://developer.ui.com/network/v10.6.106/openapi.json) and
  [11.0.97](https://developer.ui.com/network/v11.0.97/openapi.json) specs: unchanged
  44 paths/73 operations; flow reporting and radio schema additions. See fixture
  provenance/hashes in `internal/client/integration/testdata/README.md`.

New UI features do not imply new documented configuration endpoints. DHCP
reservations and device configuration still require legacy adapters. Official
network/Wi-Fi/firewall writes and resource backend migrations remain future work.
Real Network 11 tests must confirm the offered OS/Network versions, key permissions,
site/object mappings, .99 in-console schema and device provisioning. Synthetic
fixtures establish decoding/transport contracts only; no controller was contacted.

Offline slice-two client gates: `go test ./...`, `go vet ./...`, and
`go test -race ./internal/client/... ./internal/provider/base`, all with loopback
only in a network namespace and acceptance tests disabled. The base race gate
exposed an existing unlocked feature-cache read; cache lookup now holds its mutex.
The trusted plan workflow also skips draft PRs, allowing offline labels to be
attached before a PR becomes ready without a live-plan scheduling race.

## Second slice: Network 11 legacy compatibility

The legacy HTTP adapter normalizes only `dev_id_override` in configured/observed
client, group-create, station-command and fingerprint responses. Number/string,
null and empty values decode without changing the public integer schema. Invalid
numeric strings fail with a redacted diagnostic. IDs and unrelated numeric-looking
strings are never coerced. Response size is bounded; outbound writes retain their
existing contract and need real-controller validation.

Reservation refresh now treats `rest/user` configuration as authoritative and
`stat/user` IP data as optional. Missing statistics no longer removes a configured
reservation from state. Authorization/decode failures still fail refresh and
retain state. Data-source and existing-MAC adoption paths resolve the configured
client by MAC within the selected site, reject duplicates, and never reuse the
observed client's potentially different ID. Network display-name lookup rejects
ambiguity instead of returning the first match.

On Network major version 11 or newer, missing managed network, WLAN, device,
client, site, user group, port profile, static route, firewall group/rule IDs
produce an identity-reconciliation diagnostic rather than the SDK's not-found
signal that clears state. This deliberately also stops on genuine out-of-band
removal: distinguish deletion from migration with a reviewed inventory before
removing/importing state. Existing older-controller deletion behavior remains.
No IDs are automatically replaced and no display-name guess changes ownership.
Both 24-hex and UUID-shaped legacy import IDs remain opaque; empty/traversal/
ambiguous site:id forms are rejected. Importing a UUID does not switch backend.

| Target | Read evidence | Write evidence |
| --- | --- | --- |
| Network 10.6.106/109, OS not observed | Existing offline contracts and compatibility guard tests | Historical sanitized device replay only |
| Network 11.0.97, OS 6 target | Synthetic official/legacy fixtures; real SDK/HTTPS reservation refresh; new-ID device replay | Synthetic management-only device payloads; hardware unverified |
| Network 11.0.99, OS 6 target | Version guard test; .97 contract only | Unverified; .99 in-console schema needed |

Fixtures/provenance are in `internal/client/{integration,legacy}/testdata` and
`internal/provider/device/testdata`. Historical AP/switch recordings from slice
one are also replayed with explicitly synthetic UUID/unknown-field overlays.

Still requiring a real, separately authorized Network 11 controller: capture
sanitized configured versus observed client responses and ID mappings before/
after migration; confirm all integer/string/null variants and statistics absence;
verify exact Beast OS channel/build, API-key permissions and .99 local spec;
confirm reservation writes, unknown network/WLAN setting preservation, device
management/ports/radios and firewall ordering/provisioning. Current network/WLAN
replacement-write risks are not certified by successful reads. No controller,
backend, secrets, live plans, releases, merges or production state were accessed.

Compatibility local evidence: all package unit tests and vet pass; race tests for
client/base/user/network/device/firewall pass. The isolated OpenTofu 1.12.5 fixture
runner passes (two device declaration forms, policy and ordering: four creates,
zero changes/deletes in disposable empty state, zero HTTP writes). No Rust gates
were needed. Existing root/module schemas and provider dependencies are unchanged.
The public 11.0.99 OpenAPI URL returned HTTP 404 when checked live on 2026-11-02.
The compatibility diff also passes pinned golangci-lint 2.12.2 against its parent;
the official client/base packages pass that linter without a diff filter.

## Third slice: narrowly owned ticket 277 settings

Two additive Framework resources address the next P1 ticket 277 needs:
`unifi_setting_ips_mode` (`ips_mode = "ips"`) and
`unifi_setting_teleport_enabled` (`enabled = false`). They own only their named
field. Existing full `unifi_setting_ips` and `unifi_setting_teleport` contracts
are unchanged; **never manage both narrow and full resources for the same site**.
The official API's documented endpoints do not configure either setting, so
these use explicit legacy adapters, without fallback or migration. Official
firewall/network/Wi-Fi migration remains a separate coherent-family task.

Creation adopts the existing singleton; it never creates missing settings.
Import is `site:setting-id` and checks the actual ID. IDs remain opaque. Missing,
ambiguous, malformed or changed identities fail refresh/update without forgetting
state. Destroy only relinquishes ownership; it does not reset security settings.

The adapter reads a fresh raw configuration snapshot, overlays one field and
preserves every other field, including unknown fields. The fixture asserts exact
preservation of four network IDs, 35 categories, manual selection, suppressions,
Teleport subnet and unknown nested values. No-op updates send no PUT. A per-client
site/setting lock spans read/merge/write/readback. Other processes, the UI, or the
older full resources still require exclusive operational ownership. No ETag or
cross-process locking is claimed. Readback mismatch fails rather than reporting
success; refresh before retrying an ambiguous write. The legacy transport's
existing retry configuration is unchanged; keep `http_max_retries = 0` for these
read/merge/write operations to avoid replaying a stale snapshot.

No controller captures were obtained. `security-settings.json` is explicitly
synthetic; public SDK/provider fixtures inspected did not supply a reusable
recorded IPS/Teleport response. Historical recorded device regressions still run
in the full unit gate. Real sanitized settings recordings and Network 11 hardware
verification remain necessary before rollout; the synthetic fixture is not a
claim that these payloads have been observed on Beast or OS 6.

Offline evidence: full Go unit/vet and client/settings/base race gates; pinned
2.12.2 golangci-lint against this diff; Ruff/Pyright; generated resource docs from
the built schema. OpenTofu 1.12.5 plans in a loopback-only namespace check six
creates in empty state, both singleton in-place updates after refresh, stable IDs,
and converged no-ops; the mock rejects every HTTP mutation. All fixture state is
disposable. No root rollout wiring, real state, secrets, controller calls, live
plans, release, merge or Rust gate is part of this slice.
