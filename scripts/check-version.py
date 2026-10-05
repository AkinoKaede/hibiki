#!/usr/bin/env python3
"""Check a release version against the committed workspace and lockfile."""
import argparse
from pathlib import Path
import re
import tomllib


def check_version(root, version):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Version must look like 0.1.0, without a v prefix or prerelease suffix')
    workspace = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']
    if workspace['package']['version'] != version:
        raise ValueError('Release version must match Cargo.toml; run scripts/bump-version.py and commit the result before releasing')
    names = set()
    for member in workspace['members']:
        package = tomllib.loads((root / member / 'Cargo.toml').read_text())['package']
        if package.get('version') != {'workspace': True}:
            raise ValueError(f'{member} must inherit the workspace version')
        names.add(package['name'])
    project = root / 'ios/Hibiki.xcodeproj/project.pbxproj'
    if project.exists():
        marketing = set(re.findall(r'"MARKETING_VERSION" = "([^"]*)";', project.read_text()))
        if marketing != {version}:
            raise ValueError('Xcode MARKETING_VERSION does not match; use scripts/bump-version.py to update every version')
    packages = tomllib.loads((root / 'Cargo.lock').read_text())['package']
    locked = {package['name']: package['version'] for package in packages
              if package['name'] in names and 'source' not in package}
    if locked.keys() != names or any(value != version for value in locked.values()):
        raise ValueError('Cargo.lock workspace versions do not match; run scripts/bump-version.py to update Cargo.lock')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    args = parser.parse_args()
    try:
        check_version(Path(__file__).resolve().parents[1], args.version)
    except ValueError as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
