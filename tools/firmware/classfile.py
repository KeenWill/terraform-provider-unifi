"""Read Java API annotations without loading or executing vendor classes."""

import struct


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise ValueError("truncated class file")
        result = self.data[self.pos:self.pos + size].tobytes()
        self.pos += size
        return result

    def u1(self):
        return self.take(1)[0]

    def u2(self):
        return int.from_bytes(self.take(2), "big")

    def u4(self):
        return int.from_bytes(self.take(4), "big")


def parse(data):
    r = Reader(data)
    if r.take(4) != b"\xca\xfe\xba\xbe":
        raise ValueError("not a class file")
    r.take(4)  # minor and major; no class is executed
    pool = [None] * r.u2()
    index = 1
    while index < len(pool):
        tag = r.u1()
        if tag == 1:
            pool[index] = r.take(r.u2()).decode("utf-8", errors="replace")
        elif tag in (3, 4):
            pool[index] = struct.unpack(">i" if tag == 3 else ">f", r.take(4))[0]
        elif tag in (5, 6):
            pool[index] = struct.unpack(">q" if tag == 5 else ">d", r.take(8))[0]
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            pool[index] = (tag, r.u2())
        elif tag in (9, 10, 11, 12, 17, 18):
            r.take(4)
        elif tag == 15:
            r.take(3)
        else:
            raise ValueError(f"unsupported constant tag {tag}")
        index += 1

    def constant(index):
        if not 0 < index < len(pool):
            raise ValueError("invalid constant index")
        value = pool[index]
        return constant(value[1]) if isinstance(value, tuple) else value

    def annotation(a):
        name = constant(a.u2())
        values = {}
        for _ in range(a.u2()):
            key = constant(a.u2())
            values[key] = element(a)
        return {"type": name, "values": values}

    def element(a):
        tag = chr(a.u1())
        if tag in "BCDFIJSZsc":
            return constant(a.u2())
        if tag == "e":
            return {"enum": constant(a.u2()), "value": constant(a.u2())}
        if tag == "@":
            return annotation(a)
        if tag == "[":
            return [element(a) for _ in range(a.u2())]
        raise ValueError(f"unsupported annotation element {tag}")

    def attributes(a):
        result = {"annotations": [], "parameters": []}
        for _ in range(a.u2()):
            name = constant(a.u2())
            body = Reader(a.take(a.u4()))
            if name in ("RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"):
                result["annotations"].extend(annotation(body) for _ in range(body.u2()))
            elif name in ("RuntimeVisibleParameterAnnotations", "RuntimeInvisibleParameterAnnotations"):
                params = [[annotation(body) for _ in range(body.u2())]
                          for _ in range(body.u1())]
                while len(result["parameters"]) < len(params):
                    result["parameters"].append([])
                for i, items in enumerate(params):
                    result["parameters"][i].extend(items)
            elif name == "Signature":
                result["signature"] = constant(body.u2())
        return result

    def members():
        result = []
        for _ in range(r.u2()):
            access = r.u2()
            name, descriptor = constant(r.u2()), constant(r.u2())
            result.append({"name": name, "descriptor": descriptor,
                           "access": access, **attributes(r)})
        return result

    r.u2()
    name = constant(r.u2())
    parent_index = r.u2()
    parent = constant(parent_index) if parent_index else None
    interfaces = [constant(r.u2()) for _ in range(r.u2())]
    fields, methods = members(), members()
    return {"name": name, "parent": parent, "interfaces": interfaces, "fields": fields,
            "methods": methods, **attributes(r)}


def descriptors(signature):
    """Split JVM descriptors (not generic signatures) into parameter/return types."""
    result, i = [], 0
    while i < len(signature):
        if signature[i] in "()":
            i += 1
            continue
        start = i
        while i < len(signature) and signature[i] == "[":
            i += 1
        if i == len(signature):
            raise ValueError("invalid JVM descriptor")
        if signature[i] == "L":
            i = signature.index(";", i) + 1
        elif signature[i] in "BCDFIJSZV":
            i += 1
        else:
            raise ValueError("invalid JVM descriptor")
        result.append(signature[start:i])
    return result


def mappings(annotations):
    """Return declared Spring route paths and verbs; unknown verbs stay unknown."""
    for item in annotations:
        name = item["type"].rsplit("/", 1)[-1].rstrip(";")
        if name not in {"RequestMapping", "GetMapping", "PostMapping", "PutMapping",
                        "PatchMapping", "DeleteMapping"}:
            continue
        values = item["values"]
        paths = values.get("path", values.get("value", [""]))
        paths = paths if isinstance(paths, list) else [paths]
        if name == "RequestMapping":
            methods = values.get("method", [])
            methods = methods if isinstance(methods, list) else [methods]
            verbs = [method["value"] for method in methods] or ["UNKNOWN"]
        else:
            verbs = [name.removesuffix("Mapping").upper()]
        yield paths, verbs
