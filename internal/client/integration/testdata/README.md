# Official API contract fixtures

`network11/` is **synthetic**, authored 2026-11-02 from the live official
[11.0.97 OpenAPI](https://developer.ui.com/network/v11.0.97/openapi.json).
It is not a controller recording, an OS 6/Beast capture, or 11.0.99 certification.
Model/OS/firmware: fixture/not observed/not observed. API-key authentication is
simulated by loopback HTTPS tests; all identifiers, MACs and addresses are invented.

| File | Method and path below `/proxy/network/integration/v1` |
| --- | --- |
| info.json | GET `/info` |
| sites.json | GET `/sites` |
| device.json | GET `/sites/{siteId}/devices/{deviceId}` |
| policies.json | GET `/sites/{siteId}/firewall/policies` |

The public spec has an empty license object. We do not bundle it or generated
source derived wholesale from it. These small, manually authored payloads use its
field contracts with synthetic values. No upstream implementation was copied.

Live spec SHA256 receipts:

- 10.6.106: `c91054d31bcefa38d7408cb12a975dd660a7304017d781ffdbc884caaf84c75d`
- 11.0.97: `0828aa9f017cce92cd035429c7e19c933d0b3387c561aac17c468b4c2ca8be66`

Both have 44 paths / 73 operations. Changed schemas: firewall policy create/update,
read and patch (`reportFlowEnabled`), radio inventory (`txPowerMode`, `802.11ah`),
and latest radio statistics (`802.11ah`). The client intentionally provides read
models only; official resource writes require a separate complete field-ownership
and identity migration design. Missing fields on older versions stay absent.
