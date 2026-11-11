# Network 11 private API observations

These are observations from the Ubiquiti Network **11.0.99-37236-1** Linux AMD64
package and read-only controller responses. They describe interfaces; they do not
certify writes, hardware provisioning, or a supported public API. No extracted
vendor binary or JavaScript bundle is distributed here.

## Provenance

The public firmware catalog is
`https://fw-update.ubnt.com/api/firmware-latest?filter=eq~~product~~unifi`.
Select platform `uos-deb13-amd64`, version `v11.0.99-37236-1`.
The package SHA256 is
`ebf4143ef67ce4c735b6739b2c41dc63e7519240cb465cd920f4b31d39e46a9d`, verified
against the catalog's `sha256_checksum` before extraction.

The package requires Java 25 and `unifi-core >= 6.0.91`, and retains MongoDB
package dependencies for migration. [The release notes](https://community.ui.com/releases/UniFi-Network-Application-11-0-97/15662d06-8122-44e2-a1ba-af5d71b8a045)
describe the application database migration to PostgreSQL. Replacing a MongoDB
container with PostgreSQL alone does not provide the OS services it expects.

UI module numbers below identify minified modules in this exact package, not
stable public symbols. The transport helpers in `swai.7d4aac3a82085841f942.js`,
modules `323434` and `995668`, establish HTTP verbs and path construction.
`C1` uses the legacy site API, `T7` the private v2 site API. A console places
`/proxy/network` before those paths. A site reference such as `default` is not an
Integration API site UUID.

## External network lists

UI: Settings → Profiles → Network Lists, Source = External.

| Operation | Method and console-relative path |
| --- | --- |
| List | `GET /proxy/network/api/s/{site}/rest/firewallgroup` |
| Create | `POST /proxy/network/api/s/{site}/rest/firewallgroup` |
| Update | `PUT /proxy/network/api/s/{site}/rest/firewallgroup/{id}` |
| Delete | `DELETE /proxy/network/api/s/{site}/rest/firewallgroup/{id}` |

The list resource still uses `firewallgroup`; it is not the official Integration
API's traffic-matching-list model. Modules `269994` and `861428` provide CRUD.
Modules `212429`, `945328`, and `647283` in
`51375.dcc811dfa08fd98b03fa.js` provide payload conversion, enums and validation.

| Field | UI contract |
| --- | --- |
| `_id` | Existing identity on update; omit on creation. |
| `name` | Nonempty, at most 64 characters; UI checks uniqueness. |
| `group_type` | `address-group`, `ipv6-address-group`, `domain-group`, `port-group`. |
| `source` | `static` or `dynamic`; missing values are displayed as static. |
| `url` | Dynamic source URL, HTTPS, at most 1024 characters. |
| `update_interval_seconds` | Wire unit is seconds. UI offers 24, 48 or 72 hours; default display is 24 hours. |
| `group_members` | Static entries; the dynamic submission sends an empty array. Fetched members are controller output, not declared static entries. |
| `description` | String. The newer form permits 1024 characters; older forms in the same bundle permit 500. Server limits need acceptance verification. |

Only IPv4, IPv6 and domain groups offer dynamic sources. Port groups are static.
The UI prevents type changes on populated existing lists and existing dynamic
lists. Server-side transition behavior is unverified.

The package's `webapps/ROOT/api-docs/integration.json` identifies itself as 11.0.99.
Its 44 paths, 73 operations and schemas match the public [11.0.97 specification](https://developer.ui.com/network/v11.0.97/openapi.json),
except presentation metadata (version, server base and tags). It
models official static traffic lists with IPv4, IPv6 and port discriminators; it
does not specify URL sources or dynamic-domain feeds. Do not translate between
these models or IDs implicitly.

Rollback design: capture the managed list's initial declared fields and identity;
restore only those fields through a tested update and verify the result. Deleting
a newly created list must first check references. Removing a provider resource
must not delete a list adopted from an existing configuration without an explicit
lifecycle contract. These rollback operations require lab verification.

## Firewall flow reporting

UI: Policy Table / Zones, Flows Logging. It is separate from ordinary logging.

| Operation | Method and console-relative path |
| --- | --- |
| List policies | `GET /proxy/network/v2/api/site/{site}/firewall-policies` |
| Read policy | `GET /proxy/network/v2/api/site/{site}/firewall-policies/{id}` |
| Create user policy | `POST /proxy/network/v2/api/site/{site}/firewall-policies` |
| Update user policy | `PUT /proxy/network/v2/api/site/{site}/firewall-policies/{id}` |
| Update predefined policy settings | `PUT /proxy/network/v2/api/site/{site}/firewall-policies/predefined/{origin_id}` |
| Batch update | `PUT /proxy/network/v2/api/site/{site}/firewall-policies/batch` |
| Batch delete | `POST /proxy/network/v2/api/site/{site}/firewall-policies/batch-delete` |
| Reorder | `PUT /proxy/network/v2/api/site/{site}/firewall-policies/batch-reorder` |

Module `487707` defines user policy operations and ordering. Module `98144` in
`98144.0e8457e939d2e1df5572.js` renders predefined policy settings and calls a
separate route using **origin_id**, not the displayed policy's `_id`.
Its payload contains `id`, `logging` and optional `report_flow`.
The UI hides flow reporting when `report_flow_supported` is false. Observed GET
responses contain boolean `report_flow` and `report_flow_supported` on both
predefined and user policy records.

The official equivalent is `reportFlowEnabled` on
`PATCH /integration/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}`.
Official creation/update defaults that field to true when omitted. The existing
legacy provider's `logging` attribute does not control it. Prefer the official
PATCH for an additive field owner if authentication and identity mapping are
available; do not assume a private PUT has PATCH semantics.

Rollback design: retain the previous reporting value for the exact policy;
restore it without resetting ordinary logging, match criteria, action or order;
re-read and compare. Do not delete a policy just to relinquish ownership of its
reporting setting. Predefined and user policies require distinct tested paths.

## Identity and private-write requirements

Observed Network 11 legacy network and WLAN responses have UUID `_id` and
`external_id` fields plus 24-hex `legacy_id`. Observed device responses have UUID
`_id` but no `legacy_id`. This does not authorize state rewriting: match known
stable identities and diagnose ambiguity before any migration. Never use a
name-only match to adopt a device.

Before adding any private mutation:

1. Verify the test controller's exact supported application version and required
   field types; reject unknown schema versions before a write.
2. Read the current object under the resource lock. Check identity and ownership.
3. Write only declared changes. If the server needs a full document, prove that
   unowned fields survive and document concurrent-writer limitations.
4. Re-read and verify the declared values. On an ambiguous write, refresh before
   retrying; do not blindly replay a stale snapshot.
5. Exercise the corresponding rollback on the disposable controller.

Public API documentation and UI code establish contracts to investigate.
Successful live GETs establish current read shapes. Neither establishes
acceptance of a mutation. All mutation acceptance tests belong on the isolated
Network 11 controller; no production gateway writes are part of this work.
