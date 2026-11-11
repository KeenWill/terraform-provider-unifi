# Device fixtures

`recorded-ap.json` and `recorded-switch.json` are reduced, sanitized controller
response fixtures from aiounifi `tests/fixtures.py` at `e0e54201dc6fc075ef9492daac3a9aa345d16252`:
https://github.com/Kane610/aiounifi/blob/e0e54201dc6fc075ef9492daac3a9aa345d16252/tests/fixtures.py

Source constants: ACCESS_POINT_AC_PRO (U7PG2, firmware 4.0.69.10871) and
SWITCH_16_PORT_POE (US16P150, firmware 4.0.66.10832). MIT notice retained in
LICENSE.aiounifi. Retrieved 2026-11-02. Original capture date, Network version,
and OS version are not supplied upstream; these are historical recorded-shape
fixtures, **not Network 10/11 compatibility evidence**. Endpoint: legacy
GET `/api/s/default/stat/device`. The envelope is reconstructed for replay.

Sanitization uses an allowlist: model, type, firmware version, state, management
configuration and port overrides. IDs, MACs, names and profile references are
replaced consistently. Telemetry, keys, cookies, SSIDs, usernames and neighbors
are excluded. No controller was contacted. The switch's first override lacks a
port index in the source; keep it as malformed-input coverage rather than invent
an observed identity. Regression tests explicitly add synthetic management,
radio, Etherlighting and unknown-field overlays. Those additions test contracts,
not recorded controller behavior. Tests record outbound PUT bodies in memory.

`network11-ap.json` and `network11-switch.json` are **synthetic overlays**, not
new recordings: the two historical sanitized payloads above with UUID-shaped
object/network IDs, missing statistics, and an invented unmodeled port setting.
Created 2026-11-02 for Network 11 migration contracts; OS version/model provisioning
not observed. Firmware/model values retain the historical source values and do
not assert that those firmware versions work on Network 11. The missing port
index is filled synthetically. These exercise the same management-only wire
regression with new IDs. Retain the original MIT notice and provenance above.
