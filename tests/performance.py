#!/usr/bin/env python3
"""Isolated simulated-card latency report and stable steady-query message gate.

One TCP proxy on the requester link adds RTT/2 in each direction. No real keys,
reader, PIN, or user configuration is used. Timings are reports, not CI thresholds.
"""
import asyncio
import json
import re
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from integration import Device, Assuan, SERVER, wait_for, make_card, run, ROOT


class DelayProxy:
    def __init__(self, upstream):
        self.upstream = upstream
        self.delay = 0
        self.ready = threading.Event()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        assert self.ready.wait(5)

    async def pipe(self, reader, writer):
        try:
            while data := await reader.read(65536):
                await asyncio.sleep(self.delay)
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    async def accept(self, reader, writer):
        remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', self.upstream)
        await asyncio.gather(self.pipe(reader, remote_writer), self.pipe(remote_reader, writer), return_exceptions=True)

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.server = self.loop.run_until_complete(asyncio.start_server(self.accept, '127.0.0.1', 0))
        self.port = self.server.sockets[0].getsockname()[1]
        self.ready.set()
        self.loop.run_forever()
        self.server.close()
        self.loop.run_until_complete(self.server.wait_closed())
        pending = asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self.loop.close()

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class NativeAssuan(Assuan):
    def __init__(self, device):
        self.p = subprocess.Popen([str(device.root/'test-scdaemon')], env=device.env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        assert self.line().startswith(b'OK')


def card_measurement(factory):
    started = time.monotonic()
    with factory() as session:
        assert session.command(b'SERIALNO')[-1] == b'OK'
        cold = round((time.monotonic() - started) * 1000, 2)
        query = [elapsed(lambda: session.command(b'GETATTR SERIALNO')) for _ in range(5)]
        staged = elapsed(lambda: session.command(b'SETDATA ' + b'01' * 32))
        sign = elapsed(lambda: session.command(b'PKSIGN --hash=sha256 OPENPGP.1', inquiry=lambda _: [b'D 123456', b'END']))
    return dict(cold_card_ms=cold, query_ms=query, setdata_ms=staged, sign_ms=sign)


def elapsed(action):
    started = time.monotonic()
    result = action()
    if isinstance(result, list):
        assert result[-1] == b'OK', result
    return round((time.monotonic() - started) * 1000, 2)


def messages(device, kind):
    return device.log_path.read_text().count('kind="' + kind + '"')


def main():
    run(['cargo', 'build', '--locked', '--workspace'], timeout=600)
    reports = []
    with tempfile.TemporaryDirectory(prefix='hibiki-perf-', dir='/tmp') as temp:
        root = Path(temp)
        config = root / 'server.toml'
        config.write_text('listen="127.0.0.1:0"\ndatabase="db"\nallow_client_channel_creation=true\n')
        log = (root / 'server.log').open('w')
        server = subprocess.Popen([str(SERVER), '--config', str(config)], stdout=log, stderr=log)
        devices = []
        proxy = None
        try:
            port = int(wait_for(lambda: re.search(r'listening on 127.0.0.1:(\d+)', (root/'server.log').read_text())).group(1))
            proxy = DelayProxy(port)
            a = Device(root, 'requester', f'ws://127.0.0.1:{proxy.port}/hibiki')
            b = Device(root, 'provider', f'ws://127.0.0.1:{port}/hibiki')
            devices = [a, b]
            psk = root/'psk'; psk.write_text('isolated-performance-psk'); psk.chmod(0o600)
            # Invite server addresses must match. Pair through the same proxy, then
            # move only the provider connection to the direct endpoint.
            b.config.write_text(b.config.read_text().replace(f':{port}/', f':{proxy.port}/'))
            a.cli('channel', 'create', 'perf', '--psk-file', psk)
            invite = a.cli('channel', 'invite', 'perf', '--psk-file', psk).stdout.decode().strip()
            request = b.cli('channel', 'join', invite, '--no-wait').stdout.decode().split()[1]
            a.cli('channel', 'approve', 'perf', request, data=b'y\n')
            b.cli('channel', 'list')
            b.config.write_text(b.config.read_text().replace(f':{proxy.port}/', f':{port}/'))
            for device in devices:
                device.cli('use', 'perf')
                device.env['RUST_LOG'] = 'hibiki=debug,hibiki_core::session=trace'
                device.env['NO_COLOR'] = '1'
            _, _, card = make_card(b)
            native = card_measurement(lambda: NativeAssuan(b))
            a.services(timeout=30); b.services(scdaemon=True, timeout=30)
            for device in devices:
                device.start()
            for rtt in [0, 50, 100, 200]:
                proxy.delay = rtt / 2000
                started = time.monotonic()
                with Assuan(a, 'scdaemon') as session:
                    assert session.command(b'SERIALNO')[-1] == b'OK'
                    cold = round((time.monotonic() - started) * 1000, 2)
                    # Establish readiness, then count only the repeated public command.
                    session.command(b'GETATTR SERIALNO')
                    time.sleep(.3 + rtt / 1000)
                    before = (messages(a, 'query'), messages(b, 'result'))
                    samples = [elapsed(lambda: session.command(b'GETATTR SERIALNO')) for _ in range(5)]
                    after = (messages(a, 'query'), messages(b, 'result'))
                    counts = [end - start for start, end in zip(before, after)]
                    assert counts == [5, 5], f'ordinary query must be one request / one response: {counts}'
                    staged = elapsed(lambda: session.command(b'SETDATA ' + b'01' * 32))
                    sign = elapsed(lambda: session.command(b'PKSIGN --hash=sha256 OPENPGP.1', inquiry=lambda _: [b'D 123456', b'END']))
                    reports.append(dict(added_rtt_ms=rtt, cold_card_ms=cold, query_ms=samples, setdata_ms=staged, sign_ms=sign, query_messages=counts))
                wait_for(lambda: b.idle('scdaemon'))
            # Compare the same emulator through the local adapter with a stalled relay.
            a.stop()
            (a.root/'card.json').write_text(json.dumps(card))
            a.services(scdaemon=True, timeout=30)
            a.start()
            server.send_signal(signal.SIGSTOP)
            try:
                local = card_measurement(lambda: Assuan(a, 'scdaemon'))
            finally:
                server.send_signal(signal.SIGCONT)
        finally:
            for device in devices:
                device.stop(); device.kill_agent()
            if proxy:
                proxy.close()
            server.terminate(); server.wait(timeout=10); log.close()
    print(json.dumps({'schema_version': 1, 'native_stdio': native, 'local_with_stalled_relay': local, 'reports': reports}, indent=2))


if __name__ == '__main__':
    main()
