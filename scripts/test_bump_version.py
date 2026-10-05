import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bump_version', ROOT / 'scripts/bump-version.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BumpTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ('Cargo.toml', 'Cargo.lock', module.PROJECT):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, self.root / name)
        for member in tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['members']:
            (self.root / member).mkdir()
            shutil.copy2(ROOT / member / 'Cargo.toml', self.root / member / 'Cargo.toml')

    def test_updates_every_version_and_only_those(self):
        before = (self.root / 'Cargo.lock').read_text()
        module.bump(self.root, '9.8.7')
        module.checker.check_version(self.root, '9.8.7')
        after = (self.root / 'Cargo.lock').read_text()
        changed = [line for line in after.splitlines() if line not in before.splitlines()]
        self.assertTrue(changed and all(line == 'version = "9.8.7"' for line in changed))
        self.assertEqual(before.count('source ='), after.count('source ='))
        module.bump(self.root, tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version'])
        self.assertEqual(before, (self.root / 'Cargo.lock').read_text())

    def test_invalid_version_writes_nothing(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        for value in ('v1.2.3', '1.2', '1.2.3-beta.1', '01.2.3'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'without a v prefix'):
                module.bump(self.root, value)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_command_line(self):
        result = subprocess.run([sys.executable, ROOT / 'scripts/bump-version.py', 'v1'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
