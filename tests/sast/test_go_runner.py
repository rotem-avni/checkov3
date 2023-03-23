import subprocess
import unittest
from os import path


class GoRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        current_dir = path.dirname(path.realpath(__file__))
        sast_core_dir = path.join(current_dir, '..', '..', 'checkov', 'sast_core')
        if not path.exists(path.join(sast_core_dir, 'library.so')):
            proc = subprocess.Popen(['make', 'build'], cwd=sast_core_dir)  # nosec
            proc.wait()

    def testSomthing(self):
        from checkov.sast.go_runner import run_go_library
        res = run_go_library('some_dir')
        assert isinstance(res, dict)
