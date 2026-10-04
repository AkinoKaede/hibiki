import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('set_version', ROOT / 'scripts/set-version.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VersionTests(unittest.TestCase):
    def test_input_validation(self):
        module.set_version(ROOT, '1.2.3', check=True)
        for value in ('v1.2.3', '', '01.2.3', '1.2.3-beta.1', '1.2', '1.2.3\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.set_version(ROOT, value, check=True)

    def test_workspace_and_lock_follow_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in ('Cargo.toml', 'Cargo.lock'):
                shutil.copy2(ROOT / filename, root / filename)
            workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
            for member in workspace['members']:
                (root / member).mkdir()
                shutil.copy2(ROOT / member / 'Cargo.toml', root / member / 'Cargo.toml')
            before = tomllib.loads((root / 'Cargo.lock').read_text())['package']
            module.set_version(root, '2.3.4')
            self.assertEqual(tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version'], '2.3.4')
            after = tomllib.loads((root / 'Cargo.lock').read_text())['package']
            self.assertEqual([p for p in before if 'source' in p], [p for p in after if 'source' in p])
            self.assertTrue(all(p['version'] == '2.3.4' for p in after if 'source' not in p))
            once = (root / 'Cargo.lock').read_bytes()
            module.set_version(root, '2.3.4')
            self.assertEqual(once, (root / 'Cargo.lock').read_bytes())


if __name__ == '__main__':
    unittest.main()
