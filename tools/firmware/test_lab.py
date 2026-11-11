import unittest

import lab


class AcceptanceEvidenceTests(unittest.TestCase):
    def test_empty_or_skipped_selection_cannot_certify_controller(self):
        for output in ["", "ok package 0.1s [no tests to run]",
                       '{"Action":"skip","Test":"TestAccExample"}\n{"Action":"pass","Package":"p"}']:
            with self.assertRaisesRegex(RuntimeError, "passed no TestAcc"):
                lab.verify_acceptance_output(output)

    def test_requires_an_actual_named_acceptance_pass(self):
        output = '\n'.join(['{"Action":"pass","Test":"TestUnit"}',
                            '{"Action":"pass","Test":"TestAccExample"}',
                            '{"Action":"pass","Package":"p"}'])
        self.assertEqual(["TestAccExample"], lab.verify_acceptance_output(output))


if __name__ == "__main__":
    unittest.main()
