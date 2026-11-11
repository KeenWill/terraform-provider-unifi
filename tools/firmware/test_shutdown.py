import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ShutdownTests(unittest.TestCase):
    def test_term_runs_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "cleaned"
            code = '''from shutdown import install_shutdown_handler
import pathlib,sys,time
install_shutdown_handler()
try:
 print("ready",flush=True)
 time.sleep(60)
except (OSError, Exception):
 sys.exit(0)  # Poll/retry handlers must never swallow service termination.
finally:
 pathlib.Path(sys.argv[1]).write_text("cleaned")
'''
            child = subprocess.Popen([sys.executable, "-c", code, str(marker)],
                                     cwd=Path(__file__).parent, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                child.send_signal(signal.SIGTERM)
                self.assertNotEqual(child.wait(timeout=5), 0)
                self.assertEqual(marker.read_text(), "cleaned")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
