#!/usr/bin/env python3
"""Build portable-layout archives for the server and desktop client (Python 3.11+)."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Rust target triple; defaults to the host")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    target = args.target
    if target is None:
        details = subprocess.check_output(["rustc", "-vV"], text=True)
        target = next(line.removeprefix("host: ") for line in details.splitlines()
                      if line.startswith("host: "))
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", target):
        parser.error("invalid Rust target triple")
    if "linux" not in target and "apple-darwin" not in target:
        parser.error("packages support Linux and macOS only")
    with (ROOT / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["workspace"]["package"]["version"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # An explicit target directory makes artifact lookup independent of Cargo config.
    target_dir = ROOT / "target" / "packages"
    subprocess.run([
        "cargo", "build", "--locked", "--release", "--target", target,
        "--target-dir", str(target_dir), "-p", "hibiki", "-p", "hibiki-server", "--bins",
    ], cwd=ROOT, check=True)
    binaries = target_dir / target / "release"
    for name, programs, config in [
        ("hibiki", ["hibiki", "hibiki-scdaemon", "hibiki-pinentry"], "client.toml"),
        ("hibiki-server", ["hibiki-server"], "server.toml"),
    ]:
        basename = f"{name}-{version}-{target}"
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / basename
            (stage / "bin").mkdir(parents=True)
            (stage / "examples").mkdir()
            for program in programs:
                shutil.copy2(binaries / program, stage / "bin" / program)
            shutil.copy2(ROOT / "README.md", stage / "README.md")
            shutil.copy2(ROOT / "examples" / config, stage / "examples" / config)
            if name == "hibiki" and "linux" in target:
                shutil.copytree(ROOT / "packaging" / "systemd", stage / "systemd")
            archive = output / f"{basename}.tar.xz"
            with tarfile.open(archive, "w:xz") as bundle:
                bundle.add(stage, arcname=basename)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        archive.with_suffix(archive.suffix + ".sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8")
        print(archive)


if __name__ == "__main__":
    main()
