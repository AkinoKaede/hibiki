#!/usr/bin/env python3
"""Local self-signed TLS relay test; no user configuration or remote services."""
import asyncio
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'target/debug'

async def run():
    with tempfile.TemporaryDirectory(prefix='hibiki-tls-') as temp:
        root = Path(temp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
                        '-days', '1', '-subj', '/CN=wrong-host.invalid'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root/'server.toml').write_text('listen="127.0.0.1:0"\ndatabase="relay.sqlite3"\n')
        server = await asyncio.create_subprocess_exec(str(BIN/'hibiki-server'), '--config', str(root/'server.toml'), stderr=asyncio.subprocess.PIPE)
        try:
            while True:
                line = await asyncio.wait_for(server.stderr.readline(), 10)
                match = re.search(rb'listening on 127.0.0.1:(\d+)', line)
                if match:
                    port = int(match[1]); break
                assert line, 'relay exited'
            async def proxy(reader, writer):
                upstream_reader, upstream_writer = await asyncio.open_connection('127.0.0.1', port)
                async def copy(source, destination):
                    try:
                        while data := await source.read(65536):
                            destination.write(data)
                            await destination.drain()
                    finally:
                        destination.close()
                await asyncio.gather(copy(reader, upstream_writer), copy(upstream_reader, writer), return_exceptions=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'cert.pem', root/'key.pem')
            listener = await asyncio.start_server(proxy, '127.0.0.1', 0, ssl=context)
            async with listener:
                tls_port = listener.sockets[0].getsockname()[1]
                async def probe(name, url, skip, expected):
                    args = [str(BIN/'examples/provider'), str(root/name), url]
                    if skip: args.append('--skip-tls-certificate-validation')
                    client = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    online = False
                    try:
                        async with asyncio.timeout(4):
                            while raw := await client.stdout.readline():
                                if json.loads(raw).get('state') == 'online':
                                    online = True; break
                    except TimeoutError:
                        pass
                    finally:
                        client.terminate()
                        await client.wait()
                    assert online == expected, (name, online, expected)
                await probe('tls-default', f'wss://127.0.0.1:{tls_port}/hibiki', False, False)
                await probe('tls-skipped', f'wss://127.0.0.1:{tls_port}/hibiki', True, True)
                await probe('plaintext', f'ws://127.0.0.1:{port}/hibiki', False, True)
                await probe('tls-default-again', f'wss://127.0.0.1:{tls_port}/hibiki', False, False)
                print('PASS: self-signed/wrong-host TLS rejected by default, explicit bypass connects; ws needs no bypass; default remains verified')
        finally:
            server.terminate()
            await server.wait()

if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--locked', '-p', 'hibiki-server'], cwd=ROOT, check=True)
    subprocess.run(['cargo', 'build', '--locked', '-p', 'hibiki-mobile', '--example', 'provider'], cwd=ROOT, check=True)
    asyncio.run(run())
