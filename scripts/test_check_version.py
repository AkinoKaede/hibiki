import importlib.util
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_version', ROOT / 'scripts/check-version.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


module_project = 'ios/Hibiki.xcodeproj/project.pbxproj'


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ('Cargo.toml', 'Cargo.lock'):
            shutil.copy2(ROOT / name, self.root / name)
        project = self.root / module_project
        project.parent.mkdir(parents=True)
        shutil.copy2(ROOT / module_project, project)
        workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
        self.version = workspace['package']['version']
        for member in workspace['members']:
            (self.root / member).mkdir()
            shutil.copy2(ROOT / member / 'Cargo.toml', self.root / member / 'Cargo.toml')

    def test_matching_version_does_not_write(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        module.check_version(self.root, self.version)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_invalid_input(self):
        for value in ('v1.2.3', '', '01.2.3', '1.2.3-beta.1', '1.2', '1.2.3\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'without a v prefix'):
                module.check_version(self.root, value)

    def test_manifest_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'bump-version'):
            module.check_version(self.root, '999.0.0')

    def test_stale_lockfile(self):
        lock = self.root / 'Cargo.lock'
        lock.write_text(lock.read_text().replace(f'name = "hibiki"\nversion = "{self.version}"',
                                               'name = "hibiki"\nversion = "999.0.0"'))
        with self.assertRaisesRegex(ValueError, 'Cargo.lock workspace versions'):
            module.check_version(self.root, self.version)

    def test_stale_xcode_project(self):
        project = self.root / module_project
        project.write_text(project.read_text().replace(f'"MARKETING_VERSION" = "{self.version}"',
                                                       '"MARKETING_VERSION" = "999.0.0"', 1))
        with self.assertRaisesRegex(ValueError, 'MARKETING_VERSION'):
            module.check_version(self.root, self.version)

    def test_missing_workspace_package(self):
        lock = self.root / 'Cargo.lock'
        lock.write_text(lock.read_text().replace('name = "hibiki"', 'name = "missing-hibiki"'))
        with self.assertRaisesRegex(ValueError, 'Cargo.lock workspace versions'):
            module.check_version(self.root, self.version)


if __name__ == '__main__':
    unittest.main()
