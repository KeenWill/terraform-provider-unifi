"""Map bundled public OpenAPI and private Spring annotations without execution.

Private schemas are explicitly partial: custom serializers and server validation
cannot be inferred from annotations. Unknowns are evidence gaps, never acceptance.
"""

import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

from classfile import descriptors, mappings, parse

VERBS = {"get", "put", "post", "delete", "patch", "head", "options"}


def factual(value, names=False, literal=False):
    if isinstance(value, dict):
        named_maps = {"properties", "patternProperties", "$defs", "definitions", "schemas", "headers", "encoding", "links"}
        return {k: factual(v, names=k in named_maps and not names,
                           literal=literal or (not names and k in {"default", "const", "enum"}))
                for k, v in sorted(value.items())
                if names or literal or k not in {"description", "summary", "example", "examples", "externalDocs"}}
    if isinstance(value, list):
        return [factual(v, literal=literal) for v in value]
    return value


def public_surface(spec):

    def resolve(value, seen=frozenset()):
        if isinstance(value, dict):
            ref = value.get("$ref")
            if ref:
                if not isinstance(ref, str) or not ref.startswith("#/components/"):
                    raise ValueError("unsupported public reference")
                if ref in seen:
                    return {"recursiveReference": ref}
                target = spec
                try:
                    for part in ref[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                except (KeyError, TypeError):
                    raise ValueError(f"missing public component {ref}") from None
                resolved = resolve(factual(target), seen | {ref})
                siblings = {k: v for k, v in value.items() if k != "$ref"}
                if siblings:
                    return {"resolvedReference": resolved, "referenceSiblings": resolve(siblings, seen)}
                return resolved
            return {k: resolve(v, seen) for k, v in value.items()}
        if isinstance(value, list):
            return [resolve(v, seen) for v in value]
        return value

    result = []
    for path, entry in sorted(spec["paths"].items()):
        for method, operation in sorted(entry.items()):
            if method not in VERBS:
                continue
            security = operation.get("security", spec.get("security", []))
            schemes = {}
            for requirement in security:
                for name in requirement:
                    pointer = name.replace("~", "~0").replace("/", "~1")
                    schemes[name] = resolve({"$ref": "#/components/securitySchemes/" + pointer})
            result.append({"path": "/integration" + path, "method": method.upper(),
                           "source": "bundled-openapi", "schema_completeness": "documented",
                           "security": {"requirements": security, "schemes": schemes},
                           "servers": factual(operation.get("servers", entry.get("servers", spec.get("servers", [])))),
                           "request": resolve(factual(operation.get("requestBody", {}))),
                           "parameters": resolve(factual(entry.get("parameters", []) +
                                                         operation.get("parameters", []))),
                           "responses": resolve(factual(operation.get("responses", {})))})
    return result


def immediate_generic(signature):
    """Return the first immediate type argument, retaining nested containers."""
    if not signature or "<" not in signature:
        return None
    start = signature.index("<") + 1
    if signature[start:start + 1] == "+":
        start += 1
    if signature[start:start + 1] in {"", "*", "-", "T"}:
        return None
    depth = 0
    end = start
    while end < len(signature):
        char = signature[end]
        if char == "<":
            depth += 1
        elif char == ">":
            if depth == 0:
                return None
            depth -= 1
        elif char == ";" and depth == 0:
            raw = signature[start:end + 1]
            return re.sub(r"<.*>", "", raw), raw
        elif char in "ZBCSIJFD" and end == start:
            return char, char
        end += 1
    return None


def private_surface(archive):
    cache = {}

    def get_class(name):
        if name not in cache:
            try:
                info = archive.getinfo(name + ".class")
            except KeyError:
                return None
            if info.file_size > 16 * 1024 * 1024:
                raise ValueError("oversized class")
            cache[name] = parse(archive.read(info))
        return cache[name]

    def annotations_by_name(items):
        return {x["type"].rsplit("/", 1)[-1].rstrip(";"): x["values"] for x in items}

    def schema(descriptor, signature=None, seen=frozenset()):
        primitives = {"Z": "boolean", "B": "integer", "C": "string", "S": "integer",
                      "I": "integer", "J": "integer", "D": "number", "F": "number",
                      "Ljava/lang/String;": "string", "Ljava/lang/Boolean;": "boolean",
                      "Ljava/lang/Integer;": "integer", "Ljava/lang/Long;": "integer",
                      "Ljava/lang/Double;": "number", "Ljava/util/UUID;": "string"}
        if descriptor in primitives:
            return {"type": primitives[descriptor]}
        if descriptor == "V":
            return {"type": "null"}
        if descriptor.startswith("["):
            return {"type": "array", "items": schema(descriptor[1:], signature[1:] if signature and signature.startswith("[") else None, seen=seen)}
        if descriptor in {"Ljava/util/List;", "Ljava/util/Set;", "Ljava/util/Collection;"}:
            inner = immediate_generic(signature)
            return {"type": "array", "items": schema(inner[0], inner[1], seen=seen) if inner else
                    {"unknown": "generic element type"}}
        if descriptor in {"Lorg/springframework/http/ResponseEntity;", "Ljava/util/Optional;"}:
            inner = immediate_generic(signature)
            return schema(inner[0], inner[1], seen=seen) if inner else {"unknown": "generic wrapper"}
        if not descriptor.startswith("L"):
            return {"unknown": "unresolved descriptor"}
        name = descriptor[1:-1]
        if name in seen or len(seen) >= 6:
            return {"unknown": "recursive or depth-limited model"}
        cls = get_class(name)
        if cls is None:
            return {"unknown": "external or dynamic model"}
        properties, required = {}, []
        for field in cls["fields"]:
            ann = annotations_by_name(field["annotations"])
            if "JsonIgnore" in ann or field["access"] & 0x0008:
                continue
            prop = ann.get("JsonProperty", ann.get("SerializedName", {})).get("value")
            # Obfuscated field names are not JSON property names. Never guess.
            if not isinstance(prop, str) or not prop:
                continue
            item = schema(field["descriptor"], field.get("signature"), seen | {name})
            for annotation, bound in [("Min", "minimum"), ("Max", "maximum")]:
                if annotation in ann:
                    item[bound] = ann[annotation].get("value")
            properties[prop] = item
            if "NotNull" in ann or ann.get("JsonProperty", {}).get("required"):
                required.append(prop)
        parent = cls["parent"]
        if parent and parent != "java/lang/Object":
            inherited = schema("L" + parent + ";", seen=seen | {name})
            properties = {**inherited.get("properties", {}), **properties}
            required.extend(inherited.get("required", []))
        if not properties:
            return {"unknown": "no explicit serialized fields"}
        return {"type": "object", "properties": dict(sorted(properties.items())),
                "required": sorted(set(required)), "partial": True}

    routes = []
    for info in archive.infolist():
        if not info.filename.endswith(".class"):
            continue
        if info.file_size > 16 * 1024 * 1024:
            raise ValueError("oversized class")
        data = archive.read(info)
        if b"/web/bind/annotation/" not in data:
            continue
        cls = get_class(info.filename.removesuffix(".class"))
        bases = list(mappings(cls["annotations"])) or [([""], ["UNKNOWN"])]
        for member in cls["methods"]:
            method_routes = list(mappings(member["annotations"]))
            if not method_routes:
                continue
            types = descriptors(member["descriptor"])
            requests = []
            for i, annotations in enumerate(member["parameters"]):
                if "RequestBody" in annotations_by_name(annotations):
                    if i >= len(types) - 1:
                        raise ValueError("request-body parameter does not match descriptor")
                    requests.append(schema(types[i]))
            response_signature = (member.get("signature", "").split(")", 1) + [""])[1]
            response = schema(types[-1], response_signature)
            for prefixes, parent_verbs in bases:
                for paths, verbs in method_routes:
                    verbs = parent_verbs if verbs == ["UNKNOWN"] else verbs
                    for prefix in prefixes:
                        for suffix in paths:
                            path = "/" + "/".join(x.strip("/") for x in [prefix, suffix] if x)
                            for verb in verbs:
                                routes.append({"path": path, "method": verb,
                                               "source": "spring-annotation",
                                               "schema_completeness": "partial",
                                               "jvm_contract": {"descriptor": member["descriptor"], "signature": member.get("signature")},
                                               "request": requests,
                                               "responses": response})
    # Servlet mounting prefixes are deliberately not inferred from class names.
    return sorted(routes, key=lambda x: (x["path"], x["method"], json.dumps(x, sort_keys=True)))


def build(app_root):
    app_root = Path(app_root)
    spec_path = app_root / "webapps/ROOT/api-docs/integration.json"
    if not spec_path.resolve().is_relative_to(app_root.resolve()):
        raise ValueError("application specification escapes the extracted application")
    spec = json.loads(spec_path.read_text())
    jar_path = app_root / "lib/ace.jar"
    if not jar_path.resolve().is_relative_to(app_root.resolve()):
        raise ValueError("application archive escapes the extracted application")
    private = []
    if jar_path.is_file():
        with zipfile.ZipFile(jar_path) as outer:
            info = outer.getinfo("BOOT-INF/lib/internal-dependencies.jar")
            if info.file_size > 256 * 1024 * 1024:
                raise ValueError("oversized application archive")
            with zipfile.ZipFile(io.BytesIO(outer.read(info))) as inner:
                private = private_surface(inner)
    observations = []
    version = spec["info"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("unsupported application version format")
    observation_file = Path(__file__).parent / "observations" / (version + ".json")
    if observation_file.is_file() and jar_path.is_file():
        known = json.loads(observation_file.read_text())
        for evidence in known["evidence"]:
            file = app_root / evidence["file"]
            if not file.resolve().is_relative_to(app_root.resolve()) or \
                    hashlib.sha256(file.read_bytes()).hexdigest() != evidence["sha256"]:
                raise ValueError("UI observation checksum changed; remap before claiming its schema")
        observations = known["operations"]
    return {"format_version": 1, "application_version": spec["info"]["version"],
            "provenance": {"ace_sha256": hashlib.sha256(jar_path.read_bytes()).hexdigest()
                           if jar_path.is_file() else None,
                           "openapi_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest()},
            "limitations": ["Private annotation paths may require a servlet mounting prefix.",
                            "Private schemas omit custom serialization and validation.",
                            "Dynamic legacy REST dispatch and UI-only fields need separate observations.",
                            "Native console builds without ace.jar have no Java annotation map.",
                            "No vendor bytecode was executed. No mutation safety is implied."],
            "operations": public_surface(spec) + private + observations}
