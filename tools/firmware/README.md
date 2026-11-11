# Firmware compatibility pipeline

The pipeline fetches public Ubiquiti artifacts, verifies the vendor SHA256 and
size, extracts them without executing firmware, maps their API surface, compares
that surface with the last successful version, and runs controller acceptance
tests in a disposable VM containing UniFi OS Server. Vendor binaries and raw UI
bundles stay in the local cache. Nothing contacts a production controller.

Dependencies: Python 3.12+, curl, bubblewrap, dpkg-deb, squashfs-tools, QEMU,
OpenSSH, Go and the provider's acceptance-test Terraform/OpenTofu executable.
Linux user namespaces must be available. Extraction has no network and sees only
system executables, the input artifact and a fresh output directory. Package
maintainer scripts execute only inside the disposable VM during installation.

## Individual stages

Run from the repository root, using a private writable directory as `$WORK`:

```sh
python3 tools/firmware/pipeline.py fetch --product unifi \
  --platform uos-deb13-amd64 --cache "$WORK/cache"
python3 tools/firmware/pipeline.py fetch --product unifi-dream \
  --platform UDMPRO --cache "$WORK/cache"
python3 tools/firmware/pipeline.py extract "$ARTIFACT" \
  --sha256 "$VENDOR_SHA256" --output "$WORK/extracted"
python3 tools/firmware/pipeline.py map "$WORK/extracted/usr/lib/unifi" \
  --output "$WORK/surface.json"
python3 tools/firmware/pipeline.py diff "$WORK/previous.json" "$WORK/surface.json" \
  --used tools/firmware/used-api.json --output "$WORK/diff.json"
python3 -m unittest discover -s tools/firmware -v
```

Fetch selects the newest public **release** for the exact product/platform.
There is no authenticated download, guessed URL or automatic EA-channel switch.
Debian application packages and UBNT images containing one SquashFS filesystem
are supported. Unknown formats fail. Console extraction selects only the Network
application; it never flashes firmware or starts a console image.

Maps resolve public schema references at each operation, so a shared-model change
appears in the corresponding endpoint diff. The Java mapper reads Spring and
serialization annotations directly from class bytes without running the classes.
It retains overloaded routes, unknown methods and incomplete schemas. Reachable
DTO bytecode hashes are retained as conservative change evidence, including for
models whose serializer cannot be inferred; implementation-only changes can
therefore require inspection too. It does
not invent servlet prefixes, custom serializer behavior or dynamic REST routes.
Reviewed UI observations supplement these gaps only when the exact UI hashes
match. See [the endpoint observations](../../NETWORK11.md) for the associated UI
features and rollback requirements. `used-api.json` is a conservative dependency
inventory; update it whenever provider/consumer coverage changes.

The 11.0.99 application package maps 73 bundled official operations, 699 private
annotation operations and four reviewed Network List UI operations. The public
6.0.17 UDMPRO console image instead bundles native ARM Network 10.6.109. Its
public spec can be mapped, but it cannot serve as an AMD64 Java acceptance target.
The scheduler records console testing as not applicable, separately from the
actual Network package's acceptance result. A partial private schema is never
evidence that a write is safe.

## Prepared disposable backend

`lab.py` requires a prepared **flattened** qcow2 base image. Its provisioning
contract is deliberate: installing arbitrary OS dependencies on the job host or
mounting the host's writable cgroup tree is not an acceptable fallback.

The prepared image contains:

- Ubuntu 24.04 with Podman, pasta, slirp4netns, uidmap and SSH installed offline.
- User `lab`, a dedicated SSH public key and passwordless sudo inside the VM.
- The checksum-verified official UniFi OS Server 6.0.19 installer, installed
  inside the VM. Its rootless `uosserver` Podman container runs Debian 13,
  unifi-core 6.0.130, PostgreSQL and Temurin Java 25.
- The public `unifi-matter-controller` 1.0.0 AMD64 package, required by Network 11.
- A provisioned local-only owner account whose generated password is used only
  in this lab. No adopted devices, cloud account or production backup.

OS Server 6.0.19 was an early-access release at initial qualification. Its
verified installer SHA256 is
`3f9bf0f34e98f0a80d8506cc477bccbbe4394adaf16d16c93d3cd9a5fbe99a48`.
Its bundled Network 10.6.106 must be upgraded inside the VM; it is not Network 11
acceptance evidence. The Matter package SHA256 is
`141ecca87c81989d44d8bccce65a5c828c4eff91834d16eb42b846371239dabb`.

Provision with QEMU user networking `restrict=on`, no bridge, and forwards bound
only to `127.0.0.1`: host SSH to guest 22 and host HTTPS to guest 11443. Obtain
dependencies on the host and transfer their verified packages into the guest;
the guest has no outbound network. Run the vendor installer and `dpkg -i` only
there. The offline local-owner setup route is `POST /api/setup`, with `name`,
`username`, `password`, `timezone` and `updateFirmware:false`. Wait for Network
startup before provisioning and select offline setup with `POST /api/setup/offline`. Never put the generated credentials in logs.

After provisioning and checking login, shut down the VM, flatten its disk using
`qemu-img convert -O qcow2`, and record the flattened image SHA256. Store the
private SSH key and a JSON `{"api_key":"..."}` lab credential
file with mode 0600. Create this key for the local lab owner through
`POST /proxy/users/api/v2/user/{id}/keys`, with a name and `expired_at:null`.
Keep the returned `data.full_api_key` private. Username/password manifests are
also supported, but repeated acceptance provider configuration can trigger the
console login rate limit; the local lab API key avoids that. Prepared images contain lab secrets and are not published.

Example private `lab.json` (replace every path and checksum):

```json
{
  "base_image": "/private/lab/base.qcow2",
  "base_sha256": "verified-sha256-of-the-flattened-base",
  "identity_file": "/private/lab/ssh-key",
  "lab_auth_file": "/private/lab/authentication.json",
  "work_directory": "/private/lab/runs",
  "qemu": "/usr/bin/qemu-system-x86_64",
  "qemu_img": "/usr/bin/qemu-img",
  "provider_directory": "/private/provider",
  "acceptance_command": ["go", "test", "-json", "-count=1", "-parallel=1", "./internal/provider/acctest", "-run", "TestAccNetwork_basic|TestAccFirewallGroup_port_group"],
  "startup_timeout_seconds": 900,
  "acceptance_timeout_seconds": 1200
}
```

Each run verifies the base and application checksums, creates an overlay, boots a
new VM, installs the selected package inside its container, verifies the exact
Network version through authenticated HTTP, and supplies an owner-only loopback
manifest to the Go acceptance harness. A zero-test or all-skipped run fails qualification. Private diagnostics are
retained under the runner work directory. The VM and overlay are removed even when
installation or tests fail. Set Go cache paths and `TF_ACC_TERRAFORM_PATH` in the
job environment. Physical provisioning, gateway routing, radio behavior, feed
downloads and Matter discovery require separate hardware evidence.

## Schedule and notifications

`watch.py` accepts this private configuration, using absolute paths:

```json
{
  "state_directory": "/private/firmware-state",
  "used_api_file": "/private/provider/tools/firmware/used-api.json",
  "test_command": ["python3", "/private/provider/tools/firmware/lab.py", "--config", "/private/lab/lab.json"],
  "notify_command": ["coord", "notify"],
  "qualification_files": ["/private/lab/lab.json"],
  "targets": [
    {"product":"unifi-dream", "platform":"UDMPRO", "test":false},
    {"product":"unifi", "platform":"uos-deb13-amd64", "test":true}
  ]
}
```

The provided user service and timer poll daily, with a small randomized delay.
Adjust `ExecStart` to the installed reviewed checkout and configuration. Run the
service manually and inspect its receipts before enabling the timer with
`systemctl --user enable --now unifi-firmware.timer`. Installing these example
files alone does not enable a job. No GitHub-hosted Actions or dashboard is used.

An exclusive lock prevents overlapping polls. The checkout must be clean and
committed. Qualification includes the provider/tool revision, used-API rules,
job configuration and hashes of the listed lab configuration files; changing
these reruns mapping and acceptance even when firmware bytes are unchanged. Every version has a surface and
diff named by its artifact hash. `accepted.json` advances only after tests and
any required notification succeed; failures preserve the previous baseline and
write `last-run.json`. Changes to used APIs and pipeline/test failures emit a
short `coord notify` notice with a stable deduplication key, without response
bodies, credentials or vendor source. Unchanged successful artifacts do not rerun
mutation tests. Archive old cache artifacts as part of local disk maintenance;
keep receipts and maps needed to reproduce a decision.
