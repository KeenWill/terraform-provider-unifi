#!/usr/bin/env python3
"""Boot a disposable, no-egress UniFi OS VM overlay and test a Network package.

The prepared base contains a provisioned local-only UniFi OS Server container,
its OS dependencies and a lab account. No production credentials are accepted.
"""

import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pipeline
from shutdown import install_shutdown_handler


def verify_acceptance_output(output):
    passed = set()
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Action") == "pass" and event.get("Test", "").startswith("TestAcc"):
            passed.add(event["Test"])
    if not passed:
        raise RuntimeError("acceptance command passed no TestAcc tests; use go test -json and a matching selector")
    return sorted(passed)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def guest(ssh, command, **kwargs):
    return subprocess.run([*ssh, command], check=True, timeout=900, **kwargs)


def wait_ready(endpoint, auth, expected, process, timeout):
    import http.cookiejar
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("disposable VM exited before Network became ready")
        try:
            headers = {}
            if "api_key" in auth:
                headers["X-API-KEY"] = auth["api_key"]
            else:
                request = urllib.request.Request(endpoint + "/api/auth/login",
                    json.dumps(auth).encode(), {"Content-Type": "application/json"})
                with opener.open(request, timeout=15):
                    pass
            request = urllib.request.Request(endpoint + "/proxy/network/api/s/default/stat/sysinfo", headers=headers)
            with opener.open(request, timeout=15) as response:
                versions = [item.get("version") for item in json.load(response)["data"]]
            if versions == [expected]:
                return
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(5)
    raise RuntimeError("lab controller did not confirm the exact requested Network version")


def run(config, artifact, sha, version):
    artifact = Path(artifact).resolve()
    if pipeline.digest(artifact) != sha:
        raise ValueError("unverified test artifact")
    base = Path(config["base_image"]).resolve()
    if pipeline.digest(base) != config["base_sha256"]:
        raise ValueError("prepared lab base checksum changed")
    key = Path(config["identity_file"]).resolve()
    auth_path = Path(config["lab_auth_file"]).resolve()
    for private in [key, auth_path]:
        if private.stat().st_mode & 0o077:
            raise ValueError("lab credential files must be owner-only")
    auth = json.loads(auth_path.read_text())
    if set(auth) not in ({"username", "password"}, {"api_key"}):
        raise ValueError("lab authentication file must contain a local lab API key or username/password")
    root = Path(config["work_directory"]).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="unifi-acceptance-", dir=root) as temporary:
        work = Path(temporary)
        disk = work / "overlay.qcow2"
        subprocess.run([config["qemu_img"], "create", "-f", "qcow2", "-F", "qcow2",
                        "-b", str(base), str(disk)], check=True, stdout=subprocess.DEVNULL)
        ssh_port, api_port = free_port(), free_port()
        while ssh_port == api_port:
            api_port = free_port()
        endpoint = f"https://127.0.0.1:{api_port}"
        ssh = ["ssh", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(work / "hosts"),
               "-o", "ConnectTimeout=5", "-p", str(ssh_port), "lab@127.0.0.1"]
        command = [config["qemu"], "-name", "unifi-acceptance", "-machine", "q35,accel=tcg",
                   "-cpu", "max", "-smp", "4", "-m", "4096", "-display", "none",
                   "-serial", "file:" + str(work / "serial.log"),
                   "-drive", f"file={disk},format=qcow2,if=virtio",
                   "-nic", "user,model=virtio-net-pci,restrict=on,"
                   f"hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:127.0.0.1:{api_port}-:11443"]
        with (work / "qemu.log").open("w") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + config.get("startup_timeout_seconds", 900)
                while True:
                    try:
                        guest(ssh, "true", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        break
                    except subprocess.CalledProcessError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("disposable VM SSH startup failed")
                        time.sleep(3)
                subprocess.run(["scp", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                                "-o", "UserKnownHostsFile=" + str(work / "hosts"), "-P", str(ssh_port),
                                str(artifact), "lab@127.0.0.1:/home/lab/network.deb"],
                               check=True, timeout=600, stdout=subprocess.DEVNULL)
                # These fixed commands execute only inside the owned VM. Every
                # run gets a new overlay; installation cannot reach host cgroups.
                guest(ssh, "sudo install -m 644 /home/lab/network.deb /tmp/network.deb && "
                      "cd /tmp && sudo -u uosserver podman cp /tmp/network.deb uosserver:/tmp/network.deb && "
                      "sudo -u uosserver podman exec uosserver env DEBIAN_FRONTEND=noninteractive "
                      "dpkg -i /tmp/network.deb", stdout=log, stderr=log)
                wait_ready(endpoint, auth, version, process, config.get("startup_timeout_seconds", 900))
                manifest = work / "lab.json"
                manifest.write_text(json.dumps({**auth, "endpoint": endpoint, "version": version}))
                manifest.chmod(0o600)
                env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "TF_VAR_"))}
                env.update(TF_ACC="1", UNIFI_ACCTEST_LAB_FILE=str(manifest),
                           TF_ACC_PROVIDER_HOST="registry.opentofu.org", TF_ACC_PROVIDER_NAMESPACE="KeenWill")
                result = subprocess.run(config["acceptance_command"], env=env,
                                        cwd=config["provider_directory"], capture_output=True, text=True,
                                        timeout=config.get("acceptance_timeout_seconds", 1200))
                # Keep private diagnostic output, but never echo credentials or
                # controller bodies into a notification or public job summary.
                (root / "last-acceptance.jsonl").write_text(result.stdout)
                (root / "last-acceptance.stderr").write_text(result.stderr)
                result.check_returncode()
                passed = verify_acceptance_output(result.stdout)
                print(json.dumps({"version": version, "acceptance_passed": passed}))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=20)
                log.flush()
                shutil.copyfile(work / "qemu.log", root / "last-vm.log")


if __name__ == "__main__":
    install_shutdown_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    run(json.loads(args.config.read_text()), args.artifact, args.sha256, args.version)
