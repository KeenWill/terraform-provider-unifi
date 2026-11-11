#!/usr/bin/env python3
"""One scheduled firmware poll. Keeps receipts locally; publishes no vendor bytes."""

import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path

import pipeline
import surface


def run_test(command, timeout):
    # The VM, SSH and Go processes share this new process group. A timeout or
    # interrupted poll must not leave an acceptance controller running.
    process = subprocess.Popen(command, start_new_session=True)
    try:
        result = process.wait(timeout=timeout)
        if result:
            raise subprocess.CalledProcessError(result, command)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=20)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=20)
        raise


def notice(command, key, message):
    if not command:
        raise ValueError("a notification command is required")
    subprocess.run([*command, "--from", "unifi-firmware", "--key", key, message],
                   check=True, timeout=30)


def poll(target, state, used, test_command, notify_command, qualification="fixture"):
    name = target["product"] + "-" + target["platform"]
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in name):
        raise ValueError("invalid target name")
    directory = state / name
    directory.mkdir(parents=True, exist_ok=True)
    receipt = {"target": name, "test": "not-run", "qualification": qualification}
    try:
        fetched = pipeline.fetch(target["product"], target["platform"], state / "cache")
        release = fetched["release"]
        sha = release["sha256_checksum"]
        receipt.update(artifact_sha256=sha, release=release["version"])
        pointer = directory / "accepted.json"
        previous = json.loads(pointer.read_text()) if pointer.exists() else None
        if previous and previous["artifact_sha256"] == sha and previous.get("qualification") == qualification:
            return {**receipt, "test": previous["test"], "unchanged": True}
        # Extraction never shares a destination with a previous run.
        with tempfile.TemporaryDirectory(prefix="unifi-map-", dir=state) as work:
            app = pipeline.extract(fetched["artifact"], sha, Path(work) / "extracted")
            current = surface.build(app)
        pipeline.write_json(directory / (sha + ".surface.json"), current)
        delta = pipeline.compare(previous["surface"], current, used) if previous else {
            "previous_version": None, "current_version": current["application_version"],
            "changes": [], "touches_used_api": False, "initial_baseline": True}
        pipeline.write_json(directory / (sha + ".diff.json"), delta)
        if target["test"]:
            if not test_command:
                raise ValueError("application target requires an isolated acceptance runner")
            # Runner owns boot, isolation, version verification and teardown. It is
            # an argv array from trusted local configuration, never a shell string.
            run_test([*test_command, "--artifact", fetched["artifact"],
                            "--sha256", sha, "--version", current["application_version"]],
                     timeout=target.get("test_timeout_seconds", 5400))
            receipt["test"] = "passed"
        else:
            receipt["test"] = "not-applicable-console-native-image"
        if delta["touches_used_api"]:
            notice(notify_command, "api-" + sha[:20],
                   "UniFi firmware changed an API used by the provider; inspect the local firmware diff.")
        # Failed tests or notifications never advance the last successful baseline.
        pipeline.write_json(pointer, {**receipt, "surface": current})
        pipeline.write_json(directory / "last-run.json", receipt)
        return receipt
    except Exception as error:
        receipt.update(test="failed", error_type=type(error).__name__)
        pipeline.write_json(directory / "last-run.json", receipt)
        key = hashlib.sha256((name + receipt.get("artifact_sha256", "fetch")).encode()).hexdigest()[:20]
        notice(notify_command, "failure-" + key,
               "UniFi firmware pipeline failed; inspect its local receipt and start a debug lane.")
        raise


def run(config):
    state = Path(config["state_directory"]).resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / "poll.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        used = json.loads(Path(config["used_api_file"]).read_text())
        repo = Path(__file__).resolve().parents[2]
        revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True)
        if dirty:
            raise ValueError("scheduled qualification requires a clean committed provider checkout")
        inputs = {"revision": revision, "used": used, "config": config,
                  "qualification_files": {p: pipeline.digest(p) for p in config.get("qualification_files", [])}}
        qualification = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        failed = False
        for target in config["targets"]:
            try:
                print(json.dumps(poll(target, state, used, config.get("test_command"),
                                      config["notify_command"], qualification)))
            except Exception as error:
                # Do not print subprocess arguments, environment or response bodies.
                print(json.dumps({"target": target["product"], "error_type": type(error).__name__}))
                failed = True
        return int(failed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    raise SystemExit(run(json.loads(args.config.read_text())))
