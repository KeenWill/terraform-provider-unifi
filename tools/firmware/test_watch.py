import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import watch


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.target = {"product": "unifi", "platform": "uos-deb13-amd64", "test": True}
        self.pointer = self.state / "unifi-uos-deb13-amd64/accepted.json"
        self.document = {"format_version": 1, "application_version": "11.0.99",
                         "operations": []}

    def poll(self, sha, fail_test=False, fail_notice=False, changed=False):
        fetched = {"artifact": "/fixture/artifact", "release": {
            "version": "v11.0.99", "sha256_checksum": sha}}
        current = self.document if not changed else {**self.document, "operations": [{
            "source": "bundled-openapi", "method": "GET", "path": "/used"}]}
        with patch("watch.pipeline.fetch", return_value=fetched), \
                patch("watch.pipeline.extract", return_value=Path("/fixture/app")), \
                patch("watch.surface.build", return_value=current), \
                patch("watch.run_test", side_effect=subprocess.CalledProcessError(1, "test")
                      if fail_test else None) as test, \
                patch("watch.notice", side_effect=RuntimeError("notice unavailable")
                      if fail_notice else None) as notify:
            result = watch.poll(self.target, self.state, [{"path": "/used", "reason": "managed"}],
                                ["isolated-runner"], ["coord", "notify"])
            return result, test.call_count, notify.call_count

    def test_failed_acceptance_does_not_advance_successful_baseline(self):
        self.poll("a" * 64)
        before = self.pointer.read_bytes()
        with self.assertRaises(subprocess.CalledProcessError):
            self.poll("b" * 64, fail_test=True, changed=True)
        self.assertEqual(before, self.pointer.read_bytes())
        receipt = json.loads((self.pointer.parent / "last-run.json").read_text())
        self.assertEqual("failed", receipt["test"])

    def test_changed_used_api_requires_notification_before_advancing(self):
        self.poll("a" * 64)
        before = self.pointer.read_bytes()
        with self.assertRaises(RuntimeError):
            self.poll("b" * 64, changed=True, fail_notice=True)
        self.assertEqual(before, self.pointer.read_bytes())
        result, tested, notified = self.poll("b" * 64, changed=True)
        self.assertEqual(("passed", 1, 1), (result["test"], tested, notified))

    def test_unchanged_successful_artifact_does_not_repeat_mutation_tests(self):
        self.poll("a" * 64)
        result, tested, notified = self.poll("a" * 64)
        self.assertTrue(result["unchanged"])
        self.assertEqual((0, 0), (tested, notified))

    def test_missing_runner_fails_closed(self):
        with patch("watch.pipeline.fetch", return_value={"artifact": "/fixture", "release": {
                "version": "v11", "sha256_checksum": "a" * 64}}), \
                patch("watch.pipeline.extract", return_value=Path("/fixture/app")), \
                patch("watch.surface.build", return_value=self.document), patch("watch.notice"):
            with self.assertRaisesRegex(ValueError, "requires an isolated"):
                watch.poll(self.target, self.state, [], [], ["coord", "notify"])
        self.assertFalse(self.pointer.exists())


if __name__ == "__main__":
    unittest.main()
