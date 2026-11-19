import copy
import io
import zipfile
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import classfile
import pipeline
import surface


class FetchTests(unittest.TestCase):
    def record(self, version=11, platform="uos-deb13-amd64"):
        return {"product": "unifi", "platform": platform, "channel": "release",
                "version_major": version, "version_minor": 0, "version_patch": 99,
                "sha256_checksum": "a" * 64, "file_size": 12, "created": "2026-11-01"}

    def test_selection_uses_platform_channel_and_numeric_version(self):
        beta = {**self.record(20), "channel": "beta"}
        selected = pipeline.choose([self.record(9), beta, self.record(12, "arm64"),
                                    self.record(11)], "unifi", "uos-deb13-amd64")
        self.assertEqual(selected["version_major"], 11)

    def test_download_does_not_accept_local_or_credential_urls(self):
        for url in ["http://fw-download.ubnt.com/x", "https://127.0.0.1/x",
                    "https://fw-download.ubnt.com.evil.example/x",
                    "https://user:password@fw-download.ubnt.com/x"]:
            with self.subTest(url=url), patch("subprocess.run") as run:
                with self.assertRaises(ValueError):
                    pipeline.download(url, "unused")
                run.assert_not_called()

    def test_fetch_rejects_payload_that_does_not_match_catalog(self):
        record = self.record()
        record["_links"] = {"data": {"href": "https://fw-download.ubnt.com/artifact"}}
        def download(url, destination, maximum=pipeline.MAX_DOWNLOAD):
            destination.write_bytes(json.dumps({"_embedded": {"firmware": [record]}}).encode()
                                    if "firmware-latest" in url else b"bad-download")
        with tempfile.TemporaryDirectory() as directory, patch.object(pipeline, "download", download):
            with self.assertRaisesRegex(ValueError, "checksum"):
                pipeline.fetch("unifi", "uos-deb13-amd64", directory)
            self.assertFalse((Path(directory) / ("a" * 64) / "artifact").exists())

    def test_extract_refuses_unverified_bytes_before_starting_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"!<arch>\nmalformed")
            with patch.object(pipeline, "sandbox") as sandbox:
                with self.assertRaises(ValueError):
                    pipeline.extract(artifact, "0" * 64, Path(directory) / "out")
                sandbox.assert_not_called()

    def test_extract_rejects_external_application_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            artifact = base / "artifact"
            artifact.write_bytes(b"!<arch>\n")
            external = base / "outside"
            external.mkdir()
            (external / "integration.json").write_text("{}")
            def malicious_extract(command, artifact, output):
                target = output / "usr/lib/unifi/webapps/ROOT"
                target.mkdir(parents=True)
                (target / "api-docs").symlink_to(external, target_is_directory=True)
            with patch.object(pipeline, "sandbox", malicious_extract):
                with self.assertRaisesRegex(ValueError, "escapes"):
                    pipeline.extract(artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), base / "out")
            self.assertTrue((external / "integration.json").exists())
            self.assertFalse((base / "out").exists())



DEPENDS_11_0_103 = (
    "Package: unifi\nVersion: 11.0.103-37274-1\n"
    "Depends: binutils, coreutils, adduser, libcap2, curl, logrotate, mongodb-server (>= 1:3.6.0)"
    " | mongodb-10gen (>= 3.6.0) | mongodb-org-server (>= 3.6.0), mongodb-server (<< 1:5.0.0)"
    " | mongodb-10gen (<< 5.0.0) | mongodb-org-server (<< 5.0.0),\n"
    " unifi-matter-controller (= 1.0.2), unifi-core (>= 6.0.91),"
    " temurin-25-jre | openjdk-25-jre | openjdk-25-jre-headless\n"
    "Pre-Depends: debconf (>= 0.5) | debconf-2.0\n")


class DependencyTests(unittest.TestCase):
    def record(self, version, platform="uos-deb13-amd64", payload=None):
        major, minor, patch_ = (int(x) for x in version.split("."))
        payload = payload or version.encode()
        return {"product": "unifi-matter-controller", "platform": platform, "channel": "release",
                "version": "v" + version, "version_major": major, "version_minor": minor,
                "version_patch": patch_, "tags": {"deb_version": version},
                "sha256_checksum": hashlib.sha256(payload).hexdigest(), "file_size": len(payload),
                "created": "2026-11-18",
                "_links": {"data": {"href": "https://fw-download.ubnt.com/matter-" + version}}}

    def resolve(self, catalog, control=DEPENDS_11_0_103):
        queried = []
        def download(url, destination, maximum=pipeline.MAX_DOWNLOAD):
            if url.startswith(pipeline.HISTORY + "?"):
                queried.append(url)
                records = catalog if "unifi-matter-controller" in url else []
                destination.write_text(json.dumps({"_embedded": {"firmware": records}}))
            else:
                destination.write_bytes(url.rsplit("-", 1)[1].encode())
        def sandbox(command, artifact, output):
            self.assertEqual(["dpkg-deb", "--control", "/input/artifact", "/output/DEBIAN"], command)
            (output / "DEBIAN").mkdir()
            (output / "DEBIAN/control").write_text(control)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(pipeline, "download", download), patch.object(pipeline, "sandbox", sandbox):
            artifact = Path(directory) / "unifi.deb"
            artifact.write_bytes(b"!<arch>\nfixture")
            resolved = pipeline.dependencies(artifact, pipeline.digest(artifact), "uos-deb13-amd64",
                                             Path(directory) / "cache", Path(directory) / "control")
            payloads = [Path(d["artifact"]).read_bytes() for d in resolved]
        return resolved, payloads, queried

    def test_relations_parse_alternatives_versions_and_continuations(self):
        fields = pipeline.control_fields(DEPENDS_11_0_103)
        groups = pipeline.relations(fields["Depends"])
        self.assertIn([("unifi-matter-controller", "=", "1.0.2")], groups)
        self.assertIn([("curl", None, None)], groups)
        self.assertEqual(3, len(groups[6]))
        with self.assertRaises(ValueError):
            pipeline.relations("bad name (= 1)")

    def test_resolves_exact_declared_version_not_newest(self):
        catalog = [self.record("1.0.0"), self.record("1.0.2"), self.record("1.0.3"),
                   self.record("1.0.2", "uos-deb13-arm64")]
        resolved, payloads, queried = self.resolve(catalog)
        self.assertEqual(["v1.0.2"], [d["release"]["version"] for d in resolved])
        self.assertEqual([b"1.0.2"], payloads)
        self.assertEqual("uos-deb13-amd64", resolved[0]["release"]["platform"])
        # Alternative groups (mongodb, java, debconf) are left to the prepared base.
        self.assertFalse(any("mongodb" in url or "debconf" in url for url in queried))

    def test_range_relation_picks_newest_satisfying_release(self):
        control = "Package: unifi\nDepends: unifi-matter-controller (>= 1.0.1), unifi-matter-controller (<< 1.0.3)\n"
        catalog = [self.record("1.0.0"), self.record("1.0.1"), self.record("1.0.2"), self.record("1.0.3")]
        resolved, _, _ = self.resolve(catalog, control)
        self.assertEqual(["v1.0.2"], [d["release"]["version"] for d in resolved])

    def test_unpublished_required_version_fails_with_specific_error(self):
        # The 11-19 catalog: 1.0.2 exists only for arm64; amd64 has 1.0.0.
        catalog = [self.record("1.0.0"), self.record("1.0.2", "uos-deb13-arm64")]
        with self.assertRaisesRegex(pipeline.DependencyUnavailable,
                                    r"unifi-matter-controller \(= 1.0.2\) is not published .* 1.0.0$"):
            self.resolve(catalog)

    def test_names_absent_from_catalog_are_base_packages(self):
        resolved, _, queried = self.resolve([], "Package: unifi\nDepends: curl, unifi-core (>= 6.0.91)\n")
        self.assertEqual([], resolved)
        self.assertEqual(2, len(queried))

    def test_payload_must_match_catalog_checksum(self):
        record = {**self.record("1.0.2"), "sha256_checksum": "0" * 64}
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.resolve([record])


class SurfaceTests(unittest.TestCase):
    def test_documentation_named_properties_and_literal_defaults_survive_mapping(self):
        original = {"properties": {"description": {"type": "string", "description": "prose"},
                                   "example": {"type": "integer"}},
                    "default": {"description": "actual default"}, "description": "prose"}
        mapped = surface.factual(original)
        self.assertEqual({"type": "string"}, mapped["properties"]["description"])
        self.assertEqual({"type": "integer"}, mapped["properties"]["example"])
        self.assertEqual({"description": "actual default"}, mapped["default"])
        self.assertNotIn("description", mapped)
        changed = {**original, "properties": {**original["properties"], "description": {"type": "integer"}}}
        before = {"format_version": 1, "application_version": "1", "operations": [{"source": "bundled-openapi", "path": "/used", "method": "GET", "responses": mapped}]}
        after = {**before, "operations": [{**before["operations"][0], "responses": surface.factual(changed)}]}
        self.assertTrue(pipeline.compare(before, after, [{"path": "/used", "reason": "policy description"}])["touches_used_api"])

    def test_public_reference_changes_are_visible_at_the_operation(self):
        spec = {"paths": {"/v1/sites/{siteId}/networks": {"post": {
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Network"}}}}}}},
            "components": {"schemas": {"Network": {"type": "object", "properties": {
                "enabled": {"type": "boolean"}}}}}}
        before = surface.public_surface(spec)
        spec["components"]["schemas"]["Network"]["properties"]["enabled"]["type"] = "string"
        after = surface.public_surface(spec)
        diff = pipeline.compare({"format_version": 1, "application_version": "a", "operations": before},
                                {"format_version": 1, "application_version": "b", "operations": after},
                                [{"path": "*/networks", "reason": "VLANs"}])
        self.assertTrue(diff["touches_used_api"])
        self.assertEqual(diff["changes"][0]["kind"], "changed")

    def test_reusable_components_and_escaped_pointers(self):
        for category, field in [("responses", "responses"), ("requestBodies", "requestBody"), ("parameters", "parameters")]:
            reference = {"$ref": "#/components/" + category + "/Shared~1name"}
            value = {"200": reference} if field == "responses" else ([reference] if field == "parameters" else reference)
            spec = {"paths": {"/v1/sites": {"get": {field: value}}},
                    "components": {category: {"Shared/name": {"schema": {"type": "string"}}}}}
            before = surface.public_surface(spec)
            spec["components"][category]["Shared/name"]["schema"]["type"] = "integer"
            after = surface.public_surface(spec)
            diff = pipeline.compare({"format_version": 1, "application_version": "a", "operations": before},
                                    {"format_version": 1, "application_version": "b", "operations": after},
                                    [{"path": "*/sites", "reason": "used"}])
            self.assertTrue(diff["touches_used_api"])
            del spec["components"][category]["Shared/name"]
            with self.assertRaises(ValueError):
                surface.public_surface(spec)

    def test_security_inheritance_overrides_and_scheme_changes(self):
        spec = {"paths": {"/v1/sites": {"get": {}}},
                "security": [{"key": []}], "components": {"securitySchemes": {
                    "key": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}}}}
        before = surface.public_surface(spec)
        spec["components"]["securitySchemes"]["key"]["name"] = "X-NEW-KEY"
        after = surface.public_surface(spec)
        delta = pipeline.compare({"format_version": 1, "application_version": "a", "operations": before},
                                 {"format_version": 1, "application_version": "b", "operations": after},
                                 [{"path": "*/sites", "reason": "used"}])
        self.assertTrue(delta["touches_used_api"])
        spec["paths"]["/v1/sites"]["get"]["security"] = []
        self.assertEqual(surface.public_surface(spec)[0]["security"], {"requirements": [], "schemes": {}})
        del spec["paths"]["/v1/sites"]["get"]["security"]
        del spec["components"]["securitySchemes"]["key"]
        with self.assertRaises(ValueError):
            surface.public_surface(spec)

    def test_used_inventory_covers_version_and_client_statistics(self):
        rules = json.loads((Path(__file__).parent / "used-api.json").read_text())
        for path in ["/api/s/{site}/stat/sysinfo", "/api/s/{site}/stat/user/{mac}",
                     "/api/site/{site}/static-dns", "/api/site/{site}/static-dns/{id}"]:
            before = {"format_version": 1, "application_version": "a", "operations": []}
            after = {**before, "operations": [{"source": "spring-annotation", "path": path, "method": "GET"}]}
            self.assertTrue(pipeline.compare(before, after, rules)["touches_used_api"])

    def test_nested_response_containers_retain_their_shape(self):
        dto = {"name": "Dto", "parent": "java/lang/Object", "methods": [], "annotations": [],
               "fields": [{"access": 0, "descriptor": "Ljava/lang/String;", "annotations": [
                   {"type": "Lcom/fasterxml/jackson/annotation/JsonProperty;", "values": {"value": "name"}}]}]}
        controller = {"name": "Controller", "parent": "java/lang/Object", "fields": [], "annotations": [],
                      "methods": [{"descriptor": "()Lorg/springframework/http/ResponseEntity;", "parameters": [],
                                   "annotations": [{"type": "Lorg/springframework/web/bind/annotation/GetMapping;",
                                                    "values": {"value": ["/used"]}}]}]}
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("Controller.class", b"/web/bind/annotation/controller")
            archive.writestr("Dto.class", b"dto")
        def mapped(argument):
            controller["methods"][0]["signature"] = "()Lorg/springframework/http/ResponseEntity<" + argument + ">;"
            with zipfile.ZipFile(io.BytesIO(content.getvalue())) as archive, patch.object(
                    surface, "parse", side_effect=lambda data: dto if data == b"dto" else controller):
                return surface.private_surface(archive)
        array = mapped("Ljava/util/List<LDto;>;")
        single = mapped("LDto;")
        self.assertEqual(array[0]["responses"]["type"], "array")
        self.assertEqual(array[0]["responses"]["items"]["type"], "object")
        self.assertEqual(single[0]["responses"]["type"], "object")
        before = {"format_version": 1, "application_version": "a", "operations": array}
        self.assertTrue(pipeline.compare(before, {**before, "operations": single},
                                        [{"path": "/used", "reason": "used"}])["touches_used_api"])
        nested = mapped("Ljava/util/Optional<Ljava/util/List<LDto;>;>;")
        self.assertEqual(nested[0]["responses"]["type"], "array")

    def test_generic_request_body_tracks_dto_field_changes(self):
        dto = {"name": "Dto", "parent": "java/lang/Object", "methods": [], "annotations": [],
               "fields": [{"access": 0, "descriptor": "Ljava/lang/String;", "annotations": [
                   {"type": "Lcom/fasterxml/jackson/annotation/JsonProperty;", "values": {"value": "name"}}]}]}
        controller = {"name": "Controller", "parent": "java/lang/Object", "fields": [], "annotations": [],
                      "methods": [{"descriptor": "(Ljava/util/List;)V", "signature": "(Ljava/util/List<LDto;>;)V",
                                   "parameters": [[{"type": "Lorg/springframework/web/bind/annotation/RequestBody;", "values": {}}]],
                                   "annotations": [{"type": "Lorg/springframework/web/bind/annotation/PostMapping;",
                                                    "values": {"value": ["/used"]}}]}]}
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("Controller.class", b"/web/bind/annotation/controller")
            archive.writestr("Dto.class", b"dto")
        def mapped():
            with zipfile.ZipFile(io.BytesIO(content.getvalue())) as archive, patch.object(
                    surface, "parse", side_effect=lambda data: dto if data == b"dto" else controller):
                return surface.private_surface(archive)
        before = mapped()
        self.assertEqual(before[0]["request"][0]["items"]["properties"]["name"]["type"], "string")
        dto["fields"][0]["descriptor"] = "Z"
        after = mapped()
        original = {"format_version": 1, "application_version": "a", "operations": before}
        self.assertTrue(pipeline.compare(original, {**original, "operations": after},
                                        [{"path": "/used", "reason": "used"}])["touches_used_api"])
        self.assertEqual(surface.parameter_signatures("<T:Ljava/lang/Object;>(I[Ljava/lang/String;Ljava/util/List<TT;>;)V"),
                         ["I", "[Ljava/lang/String;", "Ljava/util/List<TT;>;"])

    def test_transitive_evidence_crosses_maps_and_unannotated_fields(self):
        for signature, envelope in [("()Ljava/util/Map<Ljava/lang/String;LDto;>;", False),
                                    ("()LEnvelope;", True)]:
            controller = {"name": "Controller", "parent": "java/lang/Object", "fields": [], "annotations": [],
                          "methods": [{"descriptor": "()LEnvelope;" if envelope else "()Ljava/util/Map;",
                                       "signature": signature, "parameters": [], "annotations": [
                                           {"type": "Lorg/springframework/web/bind/annotation/GetMapping;", "values": {"value": ["/used"]}}]}]}
            dto = {"name": "Dto", "parent": "java/lang/Object", "methods": [], "annotations": [], "fields": []}
            parent = {"name": "Envelope", "parent": "java/lang/Object", "methods": [], "annotations": [],
                      "fields": [{"name": "payload", "access": 1, "descriptor": "LDto;", "annotations": []}]}
            def mapped(payload):
                content = io.BytesIO()
                with zipfile.ZipFile(content, "w") as archive:
                    archive.writestr("Controller.class", b"/web/bind/annotation/controller")
                    archive.writestr("Dto.class", payload)
                    archive.writestr("Envelope.class", b"envelope")
                with zipfile.ZipFile(io.BytesIO(content.getvalue())) as archive, patch.object(
                        surface, "parse", side_effect=lambda data: parent if data == b"envelope" else
                        (controller if b"controller" in data else dto)):
                    return surface.private_surface(archive)
            before, after = mapped(b"dto-v1"), mapped(b"dto-v2")
            self.assertGreaterEqual(before[0]["model_evidence"]["reachable_class_count"], 1)
            original = {"format_version": 1, "application_version": "a", "operations": before}
            self.assertTrue(pipeline.compare(original, {**original, "operations": after},
                                            [{"path": "/used", "reason": "used"}])["touches_used_api"])

    def test_spring_parameter_and_media_contract_changes_are_visible(self):
        parameter = {"type": "Lorg/springframework/web/bind/annotation/RequestParam;",
                     "values": {"value": "mac", "required": False}}
        method = {"descriptor": "(Ljava/lang/String;)V", "parameters": [[parameter]],
                  "annotations": [{"type": "Lorg/springframework/web/bind/annotation/GetMapping;",
                                   "values": {"value": ["/used"], "produces": ["application/json"]}}]}
        controller = {"name": "Controller", "parent": "java/lang/Object", "fields": [],
                      "annotations": [], "methods": [method]}
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("Controller.class", b"/web/bind/annotation/controller")
        def mapped():
            with zipfile.ZipFile(io.BytesIO(content.getvalue())) as archive, patch.object(surface, "parse", return_value=controller):
                return surface.private_surface(archive)
        for change in [lambda: parameter["values"].update(required=True),
                       lambda: method["annotations"][0]["values"].update(produces=["text/plain"])]:
            before = mapped()
            change()
            original = {"format_version": 1, "application_version": "a", "operations": before}
            self.assertTrue(pipeline.compare(original, {**original, "operations": mapped()},
                                            [{"path": "/used", "reason": "used"}])["touches_used_api"])

    def test_unrelated_changes_do_not_trigger_used_api_signal(self):
        document = {"format_version": 1, "application_version": "a", "operations": [
            {"source": "bundled-openapi", "path": "/v1/countries", "method": "GET", "responses": {}}]}
        changed = copy.deepcopy(document)
        changed["operations"][0]["responses"] = {"type": "array"}
        diff = pipeline.compare(document, changed, [{"path": "*/networks", "reason": "VLANs"}])
        self.assertEqual(len(diff["changes"]), 1)
        self.assertFalse(diff["touches_used_api"])

    def test_overloaded_routes_are_not_silently_dropped(self):
        a = {"source": "spring-annotation", "path": "/api/example", "method": "POST", "request": "one"}
        b = {**a, "request": "two"}
        doc = {"format_version": 1, "application_version": "a", "operations": [a, b]}
        diff = pipeline.compare(doc, {**doc, "operations": [a]}, [{"path": "*", "reason": "used"}])
        self.assertTrue(diff["touches_used_api"])
        self.assertEqual(len(diff["changes"][0]["before"]), 2)

    def test_recursive_public_models_are_bounded(self):
        spec = {"paths": {"/v1/tree": {"get": {"responses": {"200": {
            "$ref": "#/components/schemas/Tree"}}}}}, "components": {"schemas": {
            "Tree": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Tree"}}}}}}
        tree = surface.public_surface(spec)[0]["responses"]["200"]
        self.assertEqual(tree["properties"]["child"], {"recursiveReference": "#/components/schemas/Tree"})

    def test_truncated_class_does_not_execute_or_silently_map(self):
        for data in [b"", b"not-a-class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41\x00\x02\x01"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                classfile.parse(data)

    def test_descriptor_array_parameters_remain_separate_from_response(self):
        self.assertEqual(classfile.descriptors("(Ljava/lang/String;[[IB)[Ljava/lang/Boolean;"),
                         ["Ljava/lang/String;", "[[I", "B", "[Ljava/lang/Boolean;"])

    def test_unspecified_request_method_is_not_claimed_as_get(self):
        ann = [{"type": "Lorg/springframework/web/bind/annotation/RequestMapping;",
                "values": {"value": ["/example"]}}]
        self.assertEqual(list(classfile.mappings(ann)), [(["/example"], ["UNKNOWN"])])


if __name__ == "__main__":
    unittest.main()
