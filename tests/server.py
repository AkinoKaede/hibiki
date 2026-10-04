#!/usr/bin/env python3
"""Exercise relay deployment settings and graceful process shutdown in isolation."""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def available_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def check_relative_database(binary, directory, with_config):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('HIBIKI_', 'XDG_'))}
    # A system relay must not require a login HOME or use client XDG paths.
    env.pop('HOME', None)
    arguments = ['--database', 'data/hibiki.sqlite3']
    base = directory
    if with_config:
        base = directory / 'deploy'
        base.mkdir(mode=0o700)
        config = base / 'server.toml'
        config.write_text('database = "data/hibiki.sqlite3"\n')
        arguments = ['--config', str(config)]
    command = [str(binary), *arguments, 'channel']
    subprocess.run([*command, 'create', 'default-path', '--server',
                    'wss://relay.example/hibiki'], cwd=directory, env=env,
                   check=True, capture_output=True, timeout=20)
    database = base / 'data' / 'hibiki.sqlite3'
    assert database.stat().st_mode & 0o777 == 0o600
    assert database.parent.stat().st_mode & 0o777 == 0o700
    assert not (directory / '.local/share/hibiki/server/hibiki.sqlite3').exists()
    if with_config:
        assert not (directory / 'data').exists()
    result = subprocess.run([*command, 'list'], cwd=directory, env=env,
                            check=True, capture_output=True, text=True, timeout=10)
    assert 'default-path' in result.stdout


def check_run(binary, directory, shutdown_signal, cli_overrides):
    config = directory / 'server.toml'
    config.write_text('listen = "invalid"\ndatabase = "unused.sqlite3"\n')
    port = available_port()
    address = f'127.0.0.1:{port}'
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('HIBIKI_', 'XDG_'))}
    env.update(HOME=str(directory), HIBIKI_SERVER_CONFIG=str(config),
               HIBIKI_SERVER_LISTEN=address,
               HIBIKI_SERVER_DATABASE=str(directory / 'env.sqlite3'),
               HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION='false')
    arguments = []
    database = directory / 'env.sqlite3'
    if cli_overrides:
        env['HIBIKI_SERVER_LISTEN'] = 'invalid'
        env['HIBIKI_SERVER_CONFIG'] = str(directory / 'missing.toml')
        arguments = ['--config', str(config), '--listen', address,
                     '--database', 'cli.sqlite3',
                     '--allow-client-channel-creation', 'true']
        database = directory / 'cli.sqlite3'
    command = [str(binary), *arguments]
    subprocess.run([*command, 'channel', 'create', 'persisted', '--server',
                    'wss://relay.example/hibiki'], env=env, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    # Run twice against the same database to cover stop/restart and persistence.
    for _ in range(2):
        with tempfile.TemporaryFile() as logs:
            process = subprocess.Popen(command, env=env, stdout=logs, stderr=logs)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        logs.seek(0)
                        raise AssertionError(logs.read().decode())
                    try:
                        with urllib.request.urlopen(f'http://{address}/healthz', timeout=1) as response:
                            assert response.status == 200
                        break
                    except (urllib.error.URLError, TimeoutError):
                        if time.monotonic() >= deadline:
                            raise AssertionError('relay did not become healthy')
                        time.sleep(0.05)
                assert database.stat().st_mode & 0o777 == 0o600
                assert not (directory / 'unused.sqlite3').exists()
                if cli_overrides:
                    assert not (directory / 'env.sqlite3').exists()
                process.send_signal(shutdown_signal)
                assert process.wait(timeout=10) == 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        result = subprocess.run([*command, 'channel', 'list'], env=env, check=True,
                                capture_output=True, text=True, timeout=10)
        assert 'persisted' in result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, default=ROOT / 'target/debug/hibiki-server')
    args = parser.parse_args()
    for with_config in [False, True]:
        with tempfile.TemporaryDirectory(prefix='hibiki-server-paths-') as temporary:
            check_relative_database(args.server.resolve(), Path(temporary), with_config)
    for cli_overrides, shutdown_signal in [(False, signal.SIGTERM), (True, signal.SIGINT)]:
        with tempfile.TemporaryDirectory(prefix='hibiki-server-test-') as temporary:
            check_run(args.server.resolve(), Path(temporary), shutdown_signal, cli_overrides)
    print('Server relative paths, environment, CLI precedence, persistence and graceful shutdown passed')


if __name__ == '__main__':
    main()
