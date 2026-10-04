#!/usr/bin/env python3
"""Isolated real relay/GnuPG + production mobile core + software ISO 7816 card.

Uses temporary generated RSA keys only. Never opens a real card or user's keyring.
"""
import json
import queue
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from integration import Device, Assuan, BIN, SERVER, ROOT, run, wait_for, make_card
from mobile_crypto import make_ecc_card, ecc_sign, ecdh


def tlv(tag, value):
    tag = bytes.fromhex(tag)
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255])
    return tag + length + value


class Card:
    def __init__(self, info):
        self.info = info
        self.verified = False
        self.tries = 3
        self.commands = []
        self.pending = b''
        self.command_data = b''

    def apdu(self, command):
        cla, ins, p1, p2 = command[:4]
        self.commands.append((ins, p1, p2))  # Header only; never PINs or payloads.
        data = b''
        if len(command) > 5:
            if command[4]:
                data = command[5:5 + command[4]]
            elif len(command) > 7:
                length = int.from_bytes(command[5:7], 'big')
                data = command[7:7 + length]
        if cla & 0x10:
            self.command_data += data
            return b'\x90\x00'
        data = self.command_data + data
        self.command_data = b''
        if ins == 0xA4:
            self.verified = False
            return b'\x90\x00'
        if ins == 0xC0:
            result, self.pending = self.pending[:200], self.pending[200:]
            return result + (bytes([0x61, min(255, len(self.pending))]) if self.pending else b'\x90\x00')
        if ins == 0xCA and (p1, p2) == (0, 0x6E):
            aid = tlv('4F', bytes.fromhex(self.info['serial']))
            historical = tlv('5F52', bytes.fromhex('00730000C0009000'))
            caps = tlv('C0', bytes.fromhex('00000000080008000000'))
            algorithms = b''
            for i in range(3):
                key = self.info['keys'][min(i, len(self.info['keys'])-1)]
                attr = bytes([1])+int(key['n'], 16).bit_length().to_bytes(2, 'big')+bytes.fromhex('002000') if 'n' in key else bytes([key['algo_id']])+bytes.fromhex(key['oid'])
                algorithms += tlv('%02X' % (0xC1+i), attr)
            status = tlv('C4', bytes([1, 127, 127, 127, self.tries, 3, 3]))
            prints = tlv('C5', b''.join(bytes.fromhex(k['fingerprint']) for k in self.info['keys']) + b'\0'*20)
            times = tlv('CD', b'\0'*12)
            return aid + historical + tlv('73', caps + algorithms + status + prints + times) + b'\x90\x00'
        if ins == 0x47 and p1 == 0x81:
            slot = {0xB6: 0, 0xB8: 1, 0xA4: 2}[data[0]]
            if slot >= len(self.info['keys']):
                return b'\x6A\x88'
            key = self.info['keys'][slot]
            if 'n' in key:
                n = int(key['n'], 16).to_bytes((int(key['n'], 16).bit_length()+7)//8, 'big')
                e = int(key['e'], 16).to_bytes(3, 'big')
                result = tlv('7F49', tlv('81', n) + tlv('82', e))
            else:
                q = bytes.fromhex(key['q'])
                if key['algorithm'] in ('ed25519', 'cv25519') and q[0] == 0x40: q = q[1:]
                result = tlv('7F49', tlv('86', q))
            if len(result) <= 200: return result + b'\x90\x00'
            # Exercise GET RESPONSE, independently of the advertised extended-length capability.
            self.pending = result[200:]
            return result[:200] + bytes([0x61, min(255, len(self.pending))])
        if ins == 0x20:
            if data != b'123456':
                self.tries -= 1
                return bytes([0x63, 0xC0 | self.tries])
            self.verified = True
            return b'\x90\x00'
        if ins == 0x2A:
            if not self.verified:
                return b'\x69\x82'
            slot = 0 if (p1, p2) == (0x9E, 0x9A) else 1
            key = self.info['keys'][slot]
            if 'n' not in key:
                if slot == 0: return ecc_sign(key, data) + b'\x90\x00'
                # Parse A6 / 7F49 / 86 TLVs, including long P-521 point lengths.
                pos = 0
                for tag in [b'\xa6', b'\x7f\x49', b'\x86']:
                    assert data[pos:pos+len(tag)] == tag; pos += len(tag)
                    size = data[pos]; pos += 1
                    if size & 128: width = size & 127; size = int.from_bytes(data[pos:pos+width], 'big'); pos += width
                return ecdh(key, data[pos:pos+size]) + b'\x90\x00'
            n, d = int(key['n'], 16), int(key['d'], 16)
            width = (n.bit_length()+7)//8
            if slot == 0:
                padded = b'\x00\x01' + b'\xff'*(width-len(data)-3) + b'\x00' + data
                output = pow(int.from_bytes(padded, 'big'), d, n).to_bytes(width, 'big')
            else:
                assert data[0] == 0
                padded = pow(int.from_bytes(data[1:], 'big'), d, n).to_bytes(width, 'big')
                assert padded[:2] == b'\x00\x02'
                output = padded[padded.index(b'\0', 2)+1:]
            return output + b'\x90\x00'
        raise AssertionError('Unexpected APDU header: %s' % command[:4].hex())


class Mobile:
    def __init__(self, root, url, card):
        self.root = root
        self.card = Card(card)
        self.delay = 0
        self.cancel = False
        self.password = '123456'
        self.events = queue.Queue()
        self.lock = threading.Lock()
        self.prompts = set()
        self.card_confirmations = 0
        self.operation_events = []  # Event kind / transport only; never PINs or payloads.
        self.before_pin_reply = None
        self.decline_card = False
        self.canceled = set()
        self.failure = None
        self.p = subprocess.Popen([str(BIN/'examples/provider'), str(root), url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def send(self, **message):
        with self.lock:
            if self.p.poll() is None:
                self.p.stdin.write(json.dumps(message)+'\n')
                self.p.stdin.flush()

    def pump(self):
        try:
            for line in self.p.stdout:
                event = json.loads(line)
                kind = event['kind']
                if kind in ('open', 'apdu'):
                    if kind == 'open':
                        self.operation_events.append(('open', event['transport']))
                    response = self.card.apdu(bytes.fromhex(event['command'])) if kind == 'apdu' else b''
                    self.send(action='reply', token=event['token'], data=response.hex())
                elif kind == 'prompt':
                    self.operation_events.append(('prompt', event.get('prompt_kind')))
                    token = event['token']
                    if event.get('prompt_kind') in ('CardUsb', 'CardNfc'):
                        self.card_confirmations += 1
                        self.send(action='reply', token=token, data='', accepted=not self.decline_card)
                        continue
                    self.prompts.add(token)
                    def reply(token=token, prompt_kind=event.get('prompt_kind')):
                        if prompt_kind == 'Pin' and self.before_pin_reply:
                            try:
                                self.before_pin_reply()
                            except Exception as error:
                                self.failure = error
                                self.send(action='reply', token=token, data='', accepted=False)
                                return
                        self.prompts.discard(token)
                        self.send(action='reply', token=token, data=self.password.encode().hex(), accepted=not self.cancel)
                    threading.Timer(self.delay, reply).start()
                elif kind == 'cancelled' and event['token'] in self.prompts:
                    self.canceled.add(event['token'])
                    self.prompts.discard(event['token'])
                self.events.put(event)
        except Exception as error:
            self.failure = error

    def wait(self, kind, timeout=25):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if self.failure:
                raise self.failure
            try:
                event = self.events.get(timeout=.2)
                if event['kind'] == 'error':
                    raise AssertionError(event)
                if event['kind'] == kind:
                    return event
            except queue.Empty:
                assert self.p.poll() is None, self.p.stderr.read()
        raise AssertionError('Timed out waiting for mobile '+kind)

    def close(self):
        self.p.terminate()
        self.p.wait(timeout=10)
        diagnostic = self.p.stderr.read()
        if diagnostic: print(diagnostic, flush=True)
        if self.failure: print("Emulator failure:", self.failure, flush=True)
        for stream in (self.p.stdin, self.p.stdout, self.p.stderr):
            stream.close()


def main():
    run(['cargo', 'build', '--locked', '--workspace'])
    # Compilation is not a protocol operation; cold CI builds need a separate budget.
    run(['cargo', 'build', '--locked', '-p', 'hibiki-mobile', '--example', 'provider'], timeout=600)
    with tempfile.TemporaryDirectory(prefix='hi-mobile-', dir='/tmp') as temp:
        root = Path(temp)
        config = root/'server.toml'
        config.write_text('listen="127.0.0.1:0"\ndatabase="relay.sqlite3"\n')
        log = (root/'server.log').open('w')
        server = subprocess.Popen([str(SERVER), '--config', str(config)], stdout=log, stderr=log)
        devices = []
        mobile = None
        try:
            port = wait_for(lambda: re.search(r'listening on 127.0.0.1:(\d+)', (root/'server.log').read_text())).group(1)
            url = 'ws://127.0.0.1:%s/hibiki' % port
            a, keygen = [Device(root, name, url) for name in ('requester', 'keygen')]
            devices = [a, keygen]
            psk = root/'psk'; psk.write_text('isolated-test-channel-psk'); psk.chmod(0o600)
            a.cli('channel', 'create', 'mobile-test', '--psk-file', psk)
            invite = a.cli('channel', 'invite', 'mobile-test').stdout.decode().strip()
            a.cli('use', 'mobile-test')
            fpr, public, card = make_card(keygen)
            a.gpg('--import', data=public)
            a.services(); a.configure_agent(); a.start()
            mobile = Mobile(root/'mobile', url, card)
            while mobile.wait('state')['state'] != 'online':
                pass
            mobile.send(action='join', invite=invite, psk=psk.read_text())
            joined = mobile.wait('joined')
            a.cli('channel', 'approve', 'mobile-test', joined['request'], data=b'y\n')
            mobile.send(action='register')
            registered = mobile.wait('registered')
            assert registered['serial'] == card['serial'] and registered['keys'] == 2
            time.sleep(1)
            a.gpg('--card-status')
            signed = a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout
            message = root/'message'; message.write_bytes(b'mobile signing')
            signature = root/'signature'; signature.write_bytes(signed)
            a.gpg('--verify', signature, message)
            encrypted = a.gpg('--trust-model', 'always', '--recipient', fpr, '--encrypt', data=b'mobile decryption').stdout
            assert a.gpg('--decrypt', data=encrypted).stdout == b'mobile decryption'
            print('PASS: mobile OpenPGP backend via real relay/GnuPG, RSA signature and decryption, split APDU responses', flush=True)

            mobile.send(action='stop');mobile.wait('stopped')
            def pending_mobile_operation():
                with sqlite3.connect(root/'relay.sqlite3') as db:
                    return db.execute('SELECT count(*) FROM operations WHERE active=1 AND deadline>?', (int(time.time()),)).fetchone()[0]
            with Assuan(a, 'pinentry') as pe:
                pe.send(b'GETPIN');wait_for(pending_mobile_operation)
                mobile.send(action='start');mobile.wait('started')
                assert pe.result()[-1]==b'OK'
            print('PASS: returning mobile app receives a still-pending offline PIN request', flush=True)

            # Discovery uses public data; each private operation requires fresh consent.
            assert mobile.card_confirmations == 2
            a.kill_agent()
            mobile.decline_card = True
            before = len(mobile.card.commands)
            with Assuan(a, 'scdaemon') as scd:
                assert scd.command(b'SERIALNO')[-1] == b'OK'
                scd.command(b'SETDATA '+b'01'*32)
                result = scd.command(b'PKSIGN --hash=sha256 OPENPGP.1', lambda _: (_ for _ in ()).throw(AssertionError('PIN requested before consent')))
                assert result[-1].startswith(b'ERR'), result
            assert len(mobile.card.commands) == before
            mobile.decline_card = False
            with Assuan(a, 'scdaemon') as scd:
                assert scd.command(b'SERIALNO')[-1] == b'OK'
                assert scd.command(b'GENKEY 1')[-1].startswith(b'ERR')
                assert scd.command(b'APDU 00A40000')[-1].startswith(b'ERR')
                scd.command(b'SETDATA '+b'01'*32)
                result = scd.command(b'PKSIGN --hash=sha256 OPENPGP.1', lambda _: [b'D wrong', b'END'])
                assert result[-1].startswith(b'ERR 87'), result
            print('PASS: per-operation card consent, prohibited commands, incorrect PIN mapping without retry', flush=True)

            # Connected USB bypasses consent; a disconnected USB-only key asks for insertion.
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='register', present=True); mobile.wait('registered')
            mobile.decline_card = True
            previous = mobile.card_confirmations
            a.gpg('--local-user', fpr, '--detach-sign', data=b'USB auto response')
            assert mobile.card_confirmations == previous

            # A USB-registered dual-interface key uses NFC when USB is absent.
            # Both signing and decryption must collect the PIN before opening NFC.
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='register', transport='usb', present=False, nfc_supported=True); mobile.wait('registered')
            mobile.decline_card = False
            for operation in ('sign', 'decrypt'):
                a.kill_agent()
                first_event = len(mobile.operation_events)
                if operation == 'sign':
                    fallback = a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout
                    signature.write_bytes(fallback)
                    a.gpg('--verify', signature, message)
                else:
                    assert a.gpg('--decrypt', data=encrypted).stdout == b'mobile decryption'
                events = mobile.operation_events[first_event:]
                assert ('prompt', 'CardNfc') in events, events
                assert ('prompt', 'CardUsb') not in events, events
                assert ('open', 'Nfc') in events and ('open', 'Usb') not in events, events
                assert events.index(('prompt', 'CardNfc')) < events.index(('prompt', 'Pin')) < events.index(('open', 'Nfc')), events
            # Insert USB during the PIN prompt after starting with no USB connection.
            # A dual-interface card must use the newly attached USB connection.
            def insert_usb_before_pin_reply():
                mobile.send(action='usb_presence', present=True)
                assert mobile.wait('usb-presence')['present']
            for operation in ('sign', 'decrypt'):
                a.kill_agent()
                mobile.send(action='usb_presence', present=False)
                assert not mobile.wait('usb-presence')['present']
                first_event = len(mobile.operation_events)
                mobile.before_pin_reply = insert_usb_before_pin_reply
                try:
                    if operation == 'sign':
                        attached = a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout
                        signature.write_bytes(attached)
                        a.gpg('--verify', signature, message)
                    else:
                        assert a.gpg('--decrypt', data=encrypted).stdout == b'mobile decryption'
                finally:
                    mobile.before_pin_reply = None
                events = mobile.operation_events[first_event:]
                assert ('prompt', 'CardNfc') in events, events
                assert ('open', 'Usb') in events and ('open', 'Nfc') not in events, events
                assert events.index(('prompt', 'CardNfc')) < events.index(('prompt', 'Pin')) < events.index(('open', 'Usb')), events
            print('PASS: USB inserted during PIN entry is used for dual-interface signing and decryption', flush=True)
            previous = mobile.card_confirmations
            mobile.decline_card = True
            print('PASS: USB-registered dual-interface key falls back to NFC; PIN precedes NFC open for signing and decryption', flush=True)

            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='register', transport='usb', present=False, nfc_supported=False); mobile.wait('registered')
            before = len(mobile.card.commands)
            with Assuan(a, 'scdaemon') as scd:
                scd.command(b'SERIALNO'); scd.command(b'SETDATA '+b'01'*32)
                assert scd.command(b'PKSIGN --hash=sha256 OPENPGP.1')[-1].startswith(b'ERR')
            assert mobile.card_confirmations == previous + 1
            assert len(mobile.card.commands) == before
            mobile.decline_card = False
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='register'); mobile.wait('registered')
            print('PASS: connected USB auto response; disconnected USB-only key asks before PIN/APDU', flush=True)

            # A different card at the second tap is rejected before VERIFY or signing.
            mobile.card.info = dict(card, serial='D2760001240103040005000099990000')
            previous = len([c for c in mobile.card.commands if c[0] == 0x20])
            with Assuan(a, 'scdaemon') as scd:
                scd.command(b'SERIALNO'); scd.command(b'SETDATA '+b'01'*32)
                result = scd.command(b'PKSIGN --hash=sha256 OPENPGP.1', lambda _: [b'D 123456', b'END'])
                assert result[-1].startswith(b'ERR'), result
            assert len([c for c in mobile.card.commands if c[0] == 0x20]) == previous
            mobile.card.info = card
            print('PASS: changed physical card rejected before PIN verification', flush=True)

            for signing, decryption in [('rsa3072', 'rsa3072'), ('rsa4096', 'rsa4096'), ('ed25519', 'cv25519'), ('nistp256', 'nistp256'), ('nistp384', 'nistp384'), ('nistp521', 'nistp521')]:
                generator = Device(root, signing, url); devices.append(generator)
                efpr, epub, ecard = make_card(generator, signing) if signing.startswith("rsa") else make_ecc_card(generator, signing, decryption)
                a.kill_agent()
                a.gpg('--import', data=epub)
                a.kill_agent()
                mobile.send(action='stop'); mobile.wait('stopped')
                mobile.send(action='start')
                while mobile.wait('state')['state'] != 'online': pass
                mobile.card = Card(ecard)
                mobile.send(action='register'); mobile.wait('registered')
                a.gpg('--card-status')
                sig = a.gpg('--local-user', efpr, '--detach-sign', data=b'ECC card signing').stdout
                message.write_bytes(b'ECC card signing'); signature.write_bytes(sig)
                a.gpg('--verify', signature, message)
                ciphertext = a.gpg('--trust-model', 'always', '--recipient', efpr, '--encrypt', data=b'ECC card decryption').stdout
                assert a.gpg('--decrypt', data=ciphertext).stdout == b'ECC card decryption'
                print('PASS: real GnuPG mobile %s signing + %s decryption' % (signing, decryption), flush=True)

            # A second desktop pinentry beats a delayed mobile UI and cancels its token.
            a.services(pinentry=True); a.restart(); mobile.delay = 2
            with Assuan(a, 'pinentry') as pin:
                assert pin.command(b'GETPIN')[-1] == b'OK'
            wait_for(lambda: mobile.canceled)
            mobile.send(action='create', name='phone-owned')
            created=mobile.wait('created')
            guest=Device(root,'guest',url); devices.append(guest)
            guest_psk=root/'guest-psk'; guest_psk.write_text(created['psk']); guest_psk.chmod(0o600)
            joined_guest=guest.cli('channel','join',created['invite'],'--psk-file',guest_psk,'--no-wait').stdout.decode().split()[1]
            mobile.send(action='pending',channel=created['channel']); pending=mobile.wait('pending')['requests']
            assert len(pending)==1 and pending[0]['id']==joined_guest and len(pending[0]['words'].split())==24
            mobile.send(action='approve',channel=created['channel'],request=joined_guest); mobile.wait('approved')
            assert b'active=true' in guest.cli('channel','list').stdout
            mobile.send(action='rotate',channel=created['channel']); assert mobile.wait('rotated')['psk']!=created['psk']
            mobile.send(action='revoke',channel=created['channel'],device=guest.id); mobile.wait('revoked')
            assert b'active=false' in guest.cli('channel','list').stdout
            mobile.send(action='leave',channel=created['channel']); mobile.wait('left')
            print('PASS: mobile create/invite, pending verification, approval, PSK rotation, revocation and leave', flush=True)
            mobile.send(action='stop'); mobile.wait('stopped')
            print('PASS: losing mobile prompt canceled; background stop cancels requests', flush=True)
        finally:
            if mobile: mobile.close()
            for device in devices:
                device.stop(); device.kill_agent()
            server.terminate(); server.wait(timeout=10); log.close()


if __name__ == '__main__':
    main()
