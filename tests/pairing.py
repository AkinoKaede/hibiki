#!/usr/bin/env python3
"""Isolated invitation/scan approval interoperability; no card or daemon needed."""
import json
import re
import selectors
import signal
import subprocess
import tempfile
from pathlib import Path
from integration import BIN, SERVER, Device, run, wait_for


class Bridge:
    def __init__(self, root, url):
        self.process = subprocess.Popen([str(BIN / 'examples/provider'), str(root), url],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
        while self.receive('state')['state'] != 'online':
            pass

    def receive(self, kind):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while True:
                assert selector.select(15), 'mobile bridge timeout'
                line = self.process.stdout.readline()
                assert line, self.process.stderr.read().decode()
                event = json.loads(line)
                if event['kind'] == kind:
                    return event
                assert event['kind'] != 'error', event

    def call(self, action, expected, **values):
        self.process.stdin.write((json.dumps(dict(action=action, **values)) + '\n').encode())
        return self.receive(expected)

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


def main():
    run(['cargo', 'build', '--locked', '-p', 'hibiki', '-p', 'hibiki-server'], timeout=600)
    run(['cargo', 'build', '--locked', '-p', 'hibiki-mobile', '--example', 'provider'], timeout=600)
    with tempfile.TemporaryDirectory(prefix='hibiki-pairing-', dir='/tmp') as directory:
        root = Path(directory)
        config = root / 'relay.toml'
        config.write_text('listen="127.0.0.1:0"\ndatabase="relay.sqlite3"\nallow_client_channel_creation=true\n')
        with (root / 'relay.log').open('w') as log:
            server = subprocess.Popen([str(SERVER), '--config', str(config)], stdout=log, stderr=log)
            mobile = None
            try:
                port = wait_for(lambda: re.search(r'listening on 127.0.0.1:(\d+)', (root / 'relay.log').read_text())).group(1)
                url = 'ws://127.0.0.1:%s/hibiki' % port
                mobile = Bridge(root / 'mobile', url)
                created = mobile.call('create', 'created', name='Pairing')
                channel = created['channel']
                guest, other = [Device(root, name, url) for name in ('guest', 'other')]

                def join(device, invite):
                    rows = device.cli('channel', 'join', invite, '--no-wait').stdout.decode().splitlines()
                    return rows[0].split()[1], next(row.split()[1] for row in rows if row.startswith('verification '))

                request, code = join(guest, created['invite'])
                assert join(guest, created['invite']) == (request, code)
                other.cli('channel', 'join', created['invite'], '--no-wait', ok=False)
                fresh = mobile.call('invite', 'invitation', channel=channel)['invite']
                second, wrong_code = join(other, fresh)
                for value in (created['invite'], wrong_code, code[:-4] + '!!!!'):
                    mobile.call('approve_verification', 'error', channel=channel, request=request, code=value)
                # Swift cancellation is explicitly forwarded across UniFFI.
                mobile.call('approve_verification', 'error', channel=channel, request=request, code=code, cancel=True)
                pending = mobile.call('pending', 'pending', channel=channel)['requests']
                assert {p['id'] for p in pending} == {request, second}
                mobile.call('approve_verification', 'approved', channel=channel, request=request, code=code)
                mobile.call('approve_verification', 'error', channel=channel, request=request, code=code)
                other.cli('channel', 'leave', 'Pairing')
                mobile.call('approve_verification', 'error', channel=channel, request=second, code=wrong_code)
                other.cli('channel', 'join', fresh, '--no-wait', ok=False)

                # An administrator denial must persist through the new request.
                run([SERVER, '--config', config, 'channel', 'revoke', channel, guest.id])
                fresh = mobile.call('invite', 'invitation', channel=channel)['invite']
                reentry, new_code = join(guest, fresh)
                assert reentry != request
                assert not json.loads(guest.cli('channel', 'list', '--json').stdout)['channels'][0]['member']
                mobile.call('approve_verification', 'error', channel=channel, request=reentry, code=code)
                guest.cli('channel', 'leave', 'Pairing')
                mobile.call('approve_verification', 'error', channel=channel, request=reentry, code=new_code)
                guest.cli('channel', 'join', fresh, '--no-wait', ok=False)
                fresh = mobile.call('invite', 'invitation', channel=channel)['invite']
                reentry, new_code = join(guest, fresh)
                mobile.call('approve_verification', 'approved', channel=channel, request=reentry, code=new_code)
                assert json.loads(guest.cli('channel', 'list', '--json').stdout)['channels'][0]['member']
                print('PASS: one-use retries, QR type/request/tamper/withdrawal rejection, cancellation, single approval and admin readmission')
            finally:
                if mobile:
                    mobile.close()
                server.send_signal(signal.SIGINT)
                server.wait(timeout=10)


if __name__ == '__main__':
    main()
