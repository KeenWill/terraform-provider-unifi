import tempfile
import unittest
from pathlib import Path

import lab


class AcceptanceEvidenceTests(unittest.TestCase):
    def test_empty_or_skipped_selection_cannot_certify_controller(self):
        for output in ["", "ok package 0.1s [no tests to run]",
                       '{"Action":"skip","Test":"TestAccExample"}\n{"Action":"pass","Package":"p"}']:
            with self.assertRaisesRegex(RuntimeError, "passed no TestAcc|skipped required tests"):
                lab.verify_acceptance_output(output)

    def test_mixed_pass_and_version_skip_does_not_certify_upgrade(self):
        output = '\n'.join(['{"Action":"pass","Test":"TestAccNetwork"}',
                            '{"Action":"skip","Test":"TestAccVersionGuardedResource"}'])
        with self.assertRaisesRegex(RuntimeError, "skipped required tests"):
            lab.verify_acceptance_output(output)

    def test_requires_an_actual_named_acceptance_pass(self):
        output = '\n'.join(['{"Action":"pass","Test":"TestUnit"}',
                            '{"Action":"pass","Test":"TestAccExample"}',
                            '{"Action":"pass","Package":"p"}'])
        self.assertEqual(["TestAccExample"], lab.verify_acceptance_output(output))


class InstallTests(unittest.TestCase):
    def test_dependencies_install_in_the_same_dpkg_transaction(self):
        command = lab.install_command(2)
        dpkg = command.split("dpkg -i ", 1)[1]
        self.assertEqual("/tmp/dependency-0.deb /tmp/dependency-1.deb /tmp/network.deb", dpkg)
        self.assertEqual(1, command.count("dpkg -i"))
        self.assertIn("podman cp /tmp/dependency-1.deb uosserver:/tmp/dependency-1.deb", command)

    def test_without_dependencies_installs_only_the_package(self):
        self.assertTrue(lab.install_command(0).endswith("dpkg -i /tmp/network.deb"))

    def test_unverified_dependency_is_refused_before_any_vm_work(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "network.deb"
            artifact.write_bytes(b"network")
            dependency = Path(directory) / "matter.deb"
            dependency.write_bytes(b"matter")
            with self.assertRaisesRegex(ValueError, "unverified dependency"):
                lab.run({}, artifact, lab.pipeline.digest(artifact), "11", [(dependency, "0" * 64)])


if __name__ == "__main__":
    unittest.main()
