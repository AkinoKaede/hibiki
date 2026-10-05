#!/usr/bin/env python3
"""Set the Rust workspace, Cargo.lock and Xcode project to one release version."""
import argparse
import importlib.util
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROJECT = 'ios/Hibiki.xcodeproj/project.pbxproj'
spec = importlib.util.spec_from_file_location('check_version', ROOT / 'scripts/check-version.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def bump(root, version):
    """Rewrite every version file under root; all edits are computed before any file is written."""
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Version must look like 0.1.0, without a v prefix or prerelease suffix')
    manifest = (root / 'Cargo.toml').read_text()
    workspace = tomllib.loads(manifest)['workspace']
    edits = {}
    edits['Cargo.toml'], count = re.subn(
        r'(\[workspace\.package\][^\[]*?\nversion = ")[^"]*(")', rf'\g<1>{version}\2', manifest, count=1, flags=re.S)
    if count != 1:
        raise ValueError('Cargo.toml has no [workspace.package] version')
    names = {tomllib.loads((root / member / 'Cargo.toml').read_text())['package']['name']
             for member in workspace['members']}
    lock = (root / 'Cargo.lock').read_text()
    for name in sorted(names):
        # Workspace packages have no source line; registry crates of the same name do.
        lock, count = re.subn(rf'(\nname = "{re.escape(name)}"\nversion = ")[^"]*("\n(?!source))',
                              rf'\g<1>{version}\2', lock)
        if count != 1:
            raise ValueError(f'Cargo.lock has no unique workspace package {name}')
    edits['Cargo.lock'] = lock
    project = (root / PROJECT).read_text()
    edits[PROJECT], count = re.subn(r'("MARKETING_VERSION" = )"[^"]*";', rf'\1"{version}";', project)
    if count == 0:
        raise ValueError('Xcode project has no MARKETING_VERSION')
    for name, text in edits.items():
        (root / name).write_text(text)
    checker.check_version(root, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', help='three-component numeric version, e.g. 0.4.0')
    args = parser.parse_args()
    try:
        bump(ROOT, args.version)
    except ValueError as error:
        parser.error(str(error))
    print(f'Set Cargo workspace, Cargo.lock and Xcode MARKETING_VERSION to {args.version}')


if __name__ == '__main__':
    main()
