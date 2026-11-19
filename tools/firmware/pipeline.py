#!/usr/bin/env python3
"""Fetch, extract, map and compare public UniFi artifacts. Never contacts a gateway."""

import argparse
import fnmatch
import hashlib
import json
import mmap
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlencode, urlparse

import surface

CATALOG = "https://fw-update.ubnt.com/api/firmware-latest"
HISTORY = "https://fw-update.ubnt.com/api/firmware"
MAX_DOWNLOAD = 4 * 1024**3


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(path)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, path, maximum=MAX_DOWNLOAD):
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname not in
            {"fw-update.ubnt.com", "fw-download.ubnt.com"} or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("artifact URL is not an allowed public vendor host")
    # No redirect following, cookies, authentication, or shell interpolation.
    # curl also works where the vendor CDN rejects urllib's default client.
    subprocess.run(["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
                    "--max-time", "600", "--retry", "2", "--retry-delay", "1",
                    "--max-filesize", str(maximum), "--output", str(path), url], check=True)


def choose(records, product, platform):
    matches = [r for r in records if r.get("product") == product and
               r.get("platform") == platform and r.get("channel") == "release"]
    if not matches:
        raise ValueError("no public release for requested product/platform")
    def version(record):
        return tuple(int(record[k]) for k in ("version_major", "version_minor", "version_patch"))
    matches.sort(key=lambda r: (version(r), r.get("created", "")), reverse=True)
    record = matches[0]
    if not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256_checksum", "")):
        raise ValueError("release has no valid SHA256")
    if not isinstance(record.get("file_size"), int) or not 0 < record["file_size"] <= MAX_DOWNLOAD:
        raise ValueError("release has no bounded file size")
    return record


def fetch(product, platform, cache):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", product + platform):
        raise ValueError("invalid product/platform")
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        catalog = Path(temporary) / "catalog.json"
        download(CATALOG + "?" + urlencode({"filter": "eq~~product~~" + product}),
                 catalog, 10 * 1024**2)
        records = json.loads(catalog.read_text())["_embedded"]["firmware"]
        return store(choose(records, product, platform), cache, Path(temporary))


def store(record, cache, temporary):
    """Download one chosen catalog record into the cache, verifying size and SHA256."""
    target = cache / record["sha256_checksum"]
    target.mkdir(exist_ok=True)
    payload = target / "artifact"
    if payload.exists() and digest(payload) != record["sha256_checksum"]:
        raise ValueError("cached artifact checksum mismatch")
    if not payload.exists():
        candidate = temporary / "artifact"
        download(record["_links"]["data"]["href"], candidate)
        if candidate.stat().st_size != record["file_size"]:
            raise ValueError("download size differs from public catalog")
        if digest(candidate) != record["sha256_checksum"]:
            raise ValueError("download checksum differs from public catalog")
        candidate.replace(payload)
    write_json(target / "release.json", record)
    return {"artifact": str(payload.resolve()), "release": record}


class DependencyUnavailable(ValueError):
    """The package requires a catalog package version the vendor has not published."""


PACKAGE = r"[a-z0-9][a-z0-9+.-]+"
DEB_VERSION = r"[A-Za-z0-9][A-Za-z0-9.+~:-]*"
RELATION = re.compile(r"(" + PACKAGE + r")(?::[a-z0-9-]+)?"
                      r"(?:\s*\(\s*(<<|<=|=|>=|>>)\s*(" + DEB_VERSION + r")\s*\))?")


def control_fields(text):
    """Parse one Debian control paragraph; continuation lines join their field."""
    fields, name = {}, None
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and name:
            fields[name] += " " + line.strip()
        elif ":" in line:
            name, value = line.split(":", 1)
            fields[name] = value.strip()
    return fields


def relations(value):
    """Debian relation field -> list of alternative groups of (name, op, version)."""
    groups = []
    for group in filter(None, (g.strip() for g in value.split(","))):
        alternatives = []
        for alternative in (a.strip() for a in group.split("|")):
            match = RELATION.fullmatch(alternative)
            if not match:
                raise ValueError("unsupported package relation in control metadata")
            alternatives.append(match.groups())
        groups.append(alternatives)
    return groups


def satisfies(version, op, wanted):
    if not re.fullmatch(DEB_VERSION, version or ""):
        return False
    return subprocess.run(["dpkg", "--compare-versions", version, op, wanted],
                          check=False).returncode == 0


def dependencies(artifact, expected_sha256, platform, cache, work):
    """Fetch the catalog packages a verified .deb declares, at the required versions.

    Every single-choice Depends/Pre-Depends entry whose name is also a product in
    the public firmware catalog for the same platform is resolved there: the
    newest release whose deb_version satisfies all of the package's relations on
    that name. Names the catalog does not publish are OS packages the prepared
    base supplies. Alternatives ("a | b") are left to the base.
    """
    artifact = Path(artifact).resolve()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or digest(artifact) != expected_sha256:
        raise ValueError("refusing to read metadata of an unverified artifact")
    output = Path(work)
    output.mkdir(parents=True, exist_ok=False)
    # Control extraction runs no maintainer script; it is sandboxed like extract().
    sandbox(["dpkg-deb", "--control", "/input/artifact", "/output/DEBIAN"], artifact, output)
    fields = control_fields((output / "DEBIAN/control").read_text())
    wanted = {}
    for field in ("Pre-Depends", "Depends"):
        for group in relations(fields.get(field, "")):
            if len(group) == 1:
                name, op, version = group[0]
                wanted.setdefault(name, []).extend([(op, version)] if op else [])
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    resolved = []
    for name, constraints in sorted(wanted.items()):
        with tempfile.TemporaryDirectory(dir=cache) as temporary:
            listing = Path(temporary) / "catalog.json"
            download(HISTORY + "?" + urlencode([("filter", "eq~~product~~" + name),
                                                ("filter", "eq~~platform~~" + platform),
                                                ("filter", "eq~~channel~~release")]),
                     listing, 10 * 1024**2)
            records = [r for r in json.loads(listing.read_text())["_embedded"]["firmware"]
                       if r.get("product") == name and r.get("platform") == platform]
            if not records:
                continue
            matches = [r for r in records if all(
                satisfies((r.get("tags") or {}).get("deb_version"), op, version)
                for op, version in constraints)]
            if not matches:
                published = sorted(str((r.get("tags") or {}).get("deb_version")) for r in records)
                required = " ".join(op + " " + version for op, version in constraints)
                raise DependencyUnavailable(f"{name} ({required}) is not published for {platform};"
                                            f" catalog has {', '.join(published)}")
            resolved.append(store(choose(matches, name, platform), cache, Path(temporary)))
    return resolved


def sandbox(command, artifact, output, check=True):
    """Only the new output directory is writable; no network or host processes."""
    output = Path(output).resolve()
    return subprocess.run(["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                    "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
                    "--setenv", "LC_ALL", "C", "--ro-bind", "/usr", "/usr",
                    "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
                    "--symlink", "usr/lib64", "/lib64", "--dir", "/etc",
                    "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
                    "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
                    "--ro-bind", str(artifact), "/input/artifact",
                    "--bind", str(output), "/output", "--chdir", "/output",
                    *command], check=check, timeout=600, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL if not check else None)


def extract(artifact, expected_sha256, destination):
    artifact = Path(artifact).resolve()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or digest(artifact) != expected_sha256:
        raise ValueError("refusing to extract an unverified artifact")
    destination = Path(destination)
    # A fresh directory prevents reuse of attacker-controlled parent symlinks.
    destination.mkdir(parents=True, exist_ok=False)
    destination = destination.resolve()
    with artifact.open("rb") as stream:
        magic = stream.read(8)
    try:
        if magic == b"!<arch>\n":
            # dpkg never executes package maintainer scripts in --extract mode.
            sandbox(["dpkg-deb", "--extract", "/input/artifact", "/output"], artifact, destination)
        elif magic.startswith(b"UBNT"):
            with artifact.open("rb") as stream, mmap.mmap(stream.fileno(), 0,
                                                          access=mmap.ACCESS_READ) as data:
                offset, candidates = -1, []
                for _ in range(32):
                    offset = data.find(b"hsqs", offset + 1)
                    if offset < 0:
                        break
                    check = sandbox(["unsquashfs", "-s", "-o", str(offset), "/input/artifact"],
                                    artifact, destination, check=False)
                    if check.returncode == 0:
                        candidates.append(offset)
                if len(candidates) != 1:
                    raise ValueError("console must contain exactly one supported SquashFS image")
            sandbox(["unsquashfs", "-no-progress", "-no-xattrs", "-processors", "2",
                     "-o", str(candidates[0]), "-d", "/output", "/input/artifact",
                     "usr/lib/unifi"], artifact, destination)
        else:
            raise ValueError("unsupported artifact format; no executable installer is run")
        app = destination / "usr/lib/unifi"
        for relative in ["webapps/ROOT/api-docs/integration.json"]:
            file = app / relative
            if not file.resolve().is_relative_to(destination) or not file.is_file():
                raise ValueError("extracted application specification is missing or escapes output")
        return app
    except BaseException:
        shutil.rmtree(destination)
        raise


def compare(previous, current, used):
    if previous.get("format_version") != current.get("format_version"):
        raise ValueError("surface format changed; establish a reviewed baseline")
    def index(document):
        result = {}
        for item in document["operations"]:
            key = item["source"] + " " + item["method"] + " " + item["path"]
            # Multiple controller overloads for one route are retained, not overwritten.
            result.setdefault(key, []).append(item)
        return {k: sorted(v, key=lambda x: json.dumps(x, sort_keys=True)) for k, v in result.items()}
    before, after = index(previous), index(current)
    changes = []
    for key in sorted(before.keys() | after.keys()):
        if before.get(key) == after.get(key):
            continue
        entry = (after.get(key) or before[key])[0]
        matched = [rule["reason"] for rule in used
                   if fnmatch.fnmatchcase(entry["path"], rule["path"]) and
                   entry["method"] in rule.get("methods", [entry["method"]])]
        changes.append({"operation": key, "kind": "added" if key not in before else
                        "removed" if key not in after else "changed",
                        "used_by": matched, "before": before.get(key), "after": after.get(key)})
    return {"previous_version": previous["application_version"],
            "current_version": current["application_version"], "changes": changes,
            "touches_used_api": any(change["used_by"] for change in changes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch_parser = sub.add_parser("fetch")
    fetch_parser.add_argument("--product", required=True)
    fetch_parser.add_argument("--platform", required=True)
    fetch_parser.add_argument("--cache", type=Path, required=True)
    extract_parser = sub.add_parser("extract")
    extract_parser.add_argument("artifact", type=Path)
    extract_parser.add_argument("--sha256", required=True)
    extract_parser.add_argument("--output", type=Path, required=True)
    map_parser = sub.add_parser("map")
    map_parser.add_argument("app_root", type=Path)
    map_parser.add_argument("--output", type=Path, required=True)
    diff_parser = sub.add_parser("diff")
    diff_parser.add_argument("previous", type=Path)
    diff_parser.add_argument("current", type=Path)
    diff_parser.add_argument("--used", type=Path, required=True)
    diff_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "fetch":
        print(json.dumps(fetch(args.product, args.platform, args.cache)))
    elif args.command == "extract":
        print(extract(args.artifact, args.sha256, args.output))
    elif args.command == "map":
        write_json(args.output, surface.build(args.app_root))
    elif args.command == "diff":
        write_json(args.output, compare(json.loads(args.previous.read_text()),
                                       json.loads(args.current.read_text()),
                                       json.loads(args.used.read_text())))


if __name__ == "__main__":
    main()
