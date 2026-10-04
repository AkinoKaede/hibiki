#!/usr/bin/env python3
"""Apply a workflow release version to an ephemeral checkout without resolving dependencies."""
import argparse
from pathlib import Path
import re
import tomllib


def set_version(root, version, check=False):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Version must look like 0.1.0, without a v prefix or prerelease suffix')
    if check:
        return
    manifest_path = root / 'Cargo.toml'
    lock_path = root / 'Cargo.lock'
    manifest = manifest_path.read_text()
    workspace = tomllib.loads(manifest)['workspace']
    names = set()
    for member in workspace['members']:
        package = tomllib.loads((root / member / 'Cargo.toml').read_text())['package']
        if package.get('version') == {'workspace': True}:
            names.add(package['name'])
    manifest, count = re.subn(
        r'(?ms)(^\[workspace\.package\]\n(?:(?!^\[).)*?^version\s*=\s*)"[^"]+"',
        lambda match: match[1] + f'"{version}"', manifest, count=1)
    if count != 1:
        raise ValueError('Cannot locate workspace package version')
    lock = lock_path.read_text()
    sections = re.split(r'(?m)(?=^\[\[package\]\]$)', lock)
    old_versions = {}
    for index, section in enumerate(sections):
        if not section.startswith('[[package]]'):
            continue
        package = tomllib.loads(section)['package'][0]
        if package['name'] in names and 'source' not in package:
            old_versions[package['name']] = package['version']
            sections[index], count = re.subn(r'(?m)^version = "[^"]+"$', f'version = "{version}"', section, count=1)
            if count != 1:
                raise ValueError('Cannot update workspace package in Cargo.lock')
    if old_versions.keys() != names:
        raise ValueError('Cargo.lock does not contain all workspace packages')
    lock = ''.join(sections)
    for name, old in old_versions.items():
        lock = lock.replace(f'"{name} {old}"', f'"{name} {version}"')
    tomllib.loads(manifest)
    tomllib.loads(lock)
    manifest_path.write_text(manifest)
    lock_path.write_text(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        set_version(Path(__file__).resolve().parents[1], args.version, args.check)
    except ValueError as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
