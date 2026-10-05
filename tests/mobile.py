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
        if ins == 0xCA and p1 == 0 and p2 == 0x7A:
            return tlv('93', bytes([0, 0, 7])) + b'\x90\x00'
        if ins == 0xCA and p1 == 0 and p2 == 0x65:
            return tlv('5B', b'DOE<<JANE') + b'\x90\x00'
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
        self.usb_present = False
        self.usb_card = None
        self.connections = {}
        self.delay = 0
        self.cancel = False
        self.pin_action = None
        self.password = '123456'
        self.events = queue.Queue()
        self.lock = threading.Lock()
        self.prompts = set()
        self.card_confirmations = 0
        self.card_prompts = set()
        self.card_delay = .05
        self.operation_events = []  # Event kind / transport only; never PINs or payloads.
        self.before_pin_reply = None
        self.before_confirm_reply = None
        self.decline_card = False
        self.canceled = set()
        self.failure = None
        self.p = subprocess.Popen([str(BIN/'examples/provider'), str(root), url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def send(self, **message):
        if message['action'] in ('usb_presence', 'record_nfc'):
            self.usb_present = message.get('present', False)
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
                        if event['transport'] == 'Usb' and not self.usb_present:
                            self.send(action='card_not_present', token=event['token'])
                            continue
                        self.connections[event['connection']] = (self.usb_card or self.card) if event['transport'] == 'Usb' else self.card
                    response = self.connections[event['connection']].apdu(bytes.fromhex(event['command'])) if kind == 'apdu' else b''
                    self.send(action='reply', token=event['token'], data=response.hex())
                elif kind == 'prompt':
                    self.operation_events.append(('prompt', event.get('prompt_kind')))
                    token = event['token']
                    if event.get('prompt_kind') in ('CardUsb', 'CardNfc'):
                        self.card_confirmations += 1
                        self.card_prompts.add(token)
                        def answer_card(token=token, decline=self.decline_card):
                            if decline: self.send(action='cancel_request', token=token)
                            else: self.send(action='reply', token=token, data='', accepted=True)
                        threading.Timer(self.card_delay, answer_card).start()
                        continue
                    self.prompts.add(token)
                    def reply(token=token, prompt_kind=event.get('prompt_kind'), action=self.pin_action, prompt=event):
                        if action:
                            self.prompts.discard(token)
                            self.send(action=action, token=token)
                            return
                        before_reply = self.before_pin_reply if prompt_kind == 'Pin' else self.before_confirm_reply if prompt_kind == 'Confirm' else None
                        if before_reply:
                            try:
                                before_reply()
                            except Exception as error:
                                self.failure = error
                                self.send(action='reply', token=token, data='', accepted=False)
                                return
                        self.prompts.discard(token)
                        if prompt.get('insertion') and not self.cancel:
                            self.send(action='continue_insertion', prompt=prompt)
                        else:
                            self.send(action='reply', token=token, data=self.password.encode().hex(), accepted=not self.cancel)
                    threading.Timer(self.delay, reply).start()
                elif kind == 'cancelled':
                    self.card_prompts.discard(event['token'])
                    if event['token'] in self.prompts:
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
    # Compilation is not a protocol operation; cold CI builds need a separate budget.
    run(['cargo', 'build', '--locked', '--workspace'], timeout=600)
    run(['cargo', 'build', '--locked', '-p', 'hibiki-mobile', '--example', 'provider'], timeout=600)
    with tempfile.TemporaryDirectory(prefix='hi-mobile-', dir='/tmp') as temp:
        root = Path(temp)
        config = root/'server.toml'
        config.write_text('listen="127.0.0.1:0"\ndatabase="relay.sqlite3"\nallow_client_channel_creation=true\n')
        log = (root/'server.log').open('w')
        server = subprocess.Popen([str(SERVER), '--config', str(config)], stdout=log, stderr=log)
        devices = []
        mobile = None
        try:
            port = wait_for(lambda: re.search(r'listening on 127.0.0.1:(\d+)', (root/'server.log').read_text())).group(1)
            url = 'ws://127.0.0.1:%s/hibiki' % port
            a, keygen = [Device(root, name, url) for name in ('requester', 'keygen')]
            devices = [a, keygen]
            a.cli('channel', 'create', 'mobile-test')
            invite = a.cli('channel', 'invite', 'mobile-test').stdout.decode().strip()
            a.cli('use', 'mobile-test')
            fpr, public, card = make_card(keygen)
            a.gpg('--import', data=public)
            a.services(); a.configure_agent(); a.start()
            mobile = Mobile(root/'mobile', url, card)
            mobile.send(action='services', pin=False, card=False); mobile.wait('services')
            while mobile.wait('state')['state'] != 'online':
                pass
            mobile.send(action='join', invite=invite)
            joined = mobile.wait('joined')
            a.cli('channel', 'approve', 'mobile-test', joined['request'], data=b'y\n')
            mobile.send(action='ping', channel=joined['channel'], device=a.id)
            latency = mobile.wait('ping')
            assert len(latency['round_trips_micros']) == 4 and all(v is not None for v in latency['round_trips_micros'])
            assert not mobile.operation_events
            members = json.loads(a.cli('device', 'list', '--json').stdout)
            mobile_id = next(d['id'] for c in members['channels'] for d in c['devices'] if not d['local'])
            reply = json.loads(a.cli('device', 'ping', mobile_id, '--channel', 'mobile-test', '--json').stdout)
            assert all(v is not None for v in reply['ping']['round_trips_micros'])
            assert not mobile.operation_events
            print('PASS: mobile/desktop Ping in both directions with services disabled', flush=True)
            mobile.send(action='record_nfc', name='', present=True)
            recorded = mobile.wait('recorded')
            assert recorded['serial'] == card['serial'] and recorded['keys'] == 2
            time.sleep(1)
            mobile.card_delay = 10
            previous = mobile.card_confirmations
            with Assuan(a, 'scdaemon') as scd:
                for _ in range(8):
                    assert scd.command(b'SERIALNO')[-1] == b'OK'
                    assert scd.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                    assert scd.command(('SWITCHCARD '+card['serial']).encode())[-1] == b'OK'
                    assert scd.command(b'READKEY OPENPGP.1')[-1] == b'OK'
                assert mobile.card_confirmations == previous, 'discovery created a mobile consent prompt'
            mobile.card_delay = .05
            wait_for(lambda: a.idle('scdaemon'))
            a.gpg('--card-status')
            assert mobile.card_confirmations == previous, 'card status requested mobile consent'
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

            a.kill_agent()
            mobile.send(action='usb_presence', present=False); mobile.wait('usb-presence')
            # The current NFC snapshot is immediately discoverable and survives reconnects.
            demand = ('SERIALNO --demand=' + card['serial']).encode()
            with Assuan(a, 'scdaemon') as scd:
                previous = mobile.card_confirmations
                for command in (b'SERIALNO', b'SERIALNO --all', demand):
                    assert scd.command(command)[-1] == b'OK'
                assert scd.command(b'SERIALNO --demand=ABCD')[-1].startswith(b'ERR 112 ')
                assert scd.command(b'RESET')[-1] == b'OK'
                assert scd.command(b'SERIALNO')[-1] == b'OK'
                assert mobile.card_confirmations == previous
                assert scd.command(b'READKEY OPENPGP.1')[-1] == b'OK'
                assert scd.command(b'GENKEY 1')[-1].startswith(b'ERR')
                assert scd.command(b'APDU 00A40000')[-1].startswith(b'ERR')
                scd.command(b'SETDATA '+b'01'*32)
                result = scd.command(b'PKSIGN --hash=sha256 OPENPGP.1', lambda _: [b'D wrong', b'END'])
                assert result[-1].startswith(b'ERR 87'), result
            assert not (root/'mobile'/'data'/'nfc-cards.bin').exists()
            mobile.send(action='clear_nfc'); mobile.wait('nfc-cleared')
            with Assuan(a, 'scdaemon') as scd:
                for command in (b'SERIALNO', demand, b'READKEY OPENPGP.1'):
                    assert scd.command(command)[-1].startswith(b'ERR'), command
            print('PASS: volatile NFC is immediately discoverable; clearing removes discovery; no registry file is written', flush=True)

            # Connected USB bypasses consent; a disconnected USB-only key asks for insertion.
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='record_nfc', present=True); mobile.wait('recorded')
            mobile.decline_card = True
            previous = mobile.card_confirmations
            a.gpg('--local-user', fpr, '--detach-sign', data=b'USB auto response')
            assert mobile.card_confirmations == previous
            # With USB inserted, the PIN sheet's X cancels the whole operation,
            # even while another device could still supply the correct PIN.
            a.kill_agent(); a.services(pinentry=True); a.mode(delay=2); a.restart()
            mobile.pin_action = 'cancel_request'
            previous_verify = len([c for c in mobile.card.commands if c[0] in (0x20, 0x2A)])
            canceled = a.gpg('--local-user', fpr, '--detach-sign', data=b'cancel connected USB', ok=False)
            assert b'cancel' in canceled.stderr.lower(), canceled.stderr
            assert len([c for c in mobile.card.commands if c[0] in (0x20, 0x2A)]) == previous_verify
            mobile.pin_action = None
            a.services(); a.restart()

            # Recorded NFC skips consent and checks USB after PIN before scanning NFC.
            # Both signing and decryption must collect the PIN before opening NFC.
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='clear_nfc'); mobile.wait('nfc-cleared')
            mobile.send(action='usb_presence', present=False); mobile.wait('usb-presence')
            mobile.decline_card = False
            first_event = len(mobile.operation_events)
            selected = a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout
            signature.write_bytes(selected)
            a.gpg('--verify', signature, message)
            events = mobile.operation_events[first_event:]
            assert events.index(('prompt', 'Confirm')) < events.index(('open', 'Nfc')) < events.index(('prompt', 'Pin')), events
            print('PASS: matching native GnuPG CONFIRM acknowledges then reads NFC and completes signing', flush=True)
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
                assert ('prompt', 'CardNfc') not in events and ('prompt', 'CardUsb') not in events, events
                assert events.index(('prompt', 'Pin')) < events.index(('open', 'Usb')) < events.index(('open', 'Nfc')), events
            # Insert USB during the PIN prompt after starting with no USB connection.
            # The actual USB card must win after the PIN reply.
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
                assert ('prompt', 'CardNfc') not in events, events
                assert ('open', 'Nfc') not in events, events
                assert events.index(('prompt', 'Pin')) < events.index(('open', 'Usb')), events
            print('PASS: inserting USB during PIN entry uses USB without opening NFC', flush=True)
            # A wrong USB card is inspected but must never receive VERIFY.
            wrong_usb = Card(dict(card, serial='D2760001240103040005000099990000'))
            def replace_usb_before_pin_reply():
                mobile.usb_card = wrong_usb
            mobile.before_pin_reply = replace_usb_before_pin_reply
            a.kill_agent()
            first_event = len(mobile.operation_events)
            signature.write_bytes(a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout)
            a.gpg('--verify', signature, message)
            events = mobile.operation_events[first_event:]
            after_pin = events[events.index(('prompt', 'Pin')):]
            assert after_pin.index(('open', 'Usb')) < after_pin.index(('open', 'Nfc')), events
            assert not any(c[0] in (0x20, 0x2A) for c in mobile.usb_card.commands)
            mobile.usb_card = None
            mobile.before_pin_reply = None
            print('PASS: wrong USB card receives no PIN; matching NFC completes signing', flush=True)

            # PIN may come from another device; the card provider selects USB/NFC.
            a.kill_agent(); a.services(pinentry=True); a.mode(password='123456'); a.restart()
            mobile.send(action='services', pin=False, card=True); mobile.wait('services')
            mobile.send(action='usb_presence', present=False); mobile.wait('usb-presence')
            first_event = len(mobile.operation_events)
            signature.write_bytes(a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout)
            a.gpg('--verify', signature, message)
            events = mobile.operation_events[first_event:]
            assert ('prompt', 'Pin') not in events and ('open', 'Nfc') in events, events
            mobile.send(action='services', pin=True, card=True); mobile.wait('services')
            a.services(); a.restart()

            # No registration is needed for a USB-discovered target, even if
            # the user removes it during PIN entry and then uses NFC.
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='clear_nfc'); mobile.wait('nfc-cleared')
            mobile.send(action='start'); mobile.wait('started')
            def remove_usb_before_pin_reply():
                mobile.send(action='usb_presence', present=False)
                assert not mobile.wait('usb-presence')['present']
            for operation in ('sign', 'decrypt'):
                a.kill_agent()
                mobile.send(action='usb_presence', present=True); mobile.wait('usb-presence')
                mobile.before_pin_reply = remove_usb_before_pin_reply
                first_event = len(mobile.operation_events)
                try:
                    if operation == 'sign':
                        signature.write_bytes(a.gpg('--local-user', fpr, '--detach-sign', data=b'mobile signing').stdout)
                        a.gpg('--verify', signature, message)
                    else:
                        assert a.gpg('--decrypt', data=encrypted).stdout == b'mobile decryption'
                finally:
                    mobile.before_pin_reply = None
                events = mobile.operation_events[first_event:]
                after_pin = events[events.index(('prompt', 'Pin')):]
                assert after_pin.index(('open', 'Usb')) < after_pin.index(('open', 'Nfc')), events
                assert ('prompt', 'CardNfc') not in events, events
            print('PASS: unregistered USB card removed during PIN entry falls back to NFC for sign/decrypt; remote PIN also works', flush=True)
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='record_nfc'); mobile.wait('recorded')
            previous = mobile.card_confirmations
            mobile.decline_card = True
            print('PASS: recorded NFC skips consent; PIN precedes USB probe and NFC scan for signing and decryption', flush=True)

            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='nfc_capability', available=False); mobile.wait('nfc-capability')
            mobile.send(action='usb_presence', present=False); mobile.wait('usb-presence')
            mobile.decline_card = False
            before = len(mobile.card.commands)
            previous = mobile.card_confirmations
            with Assuan(a, 'scdaemon') as scd:
                assert scd.command(demand)[-1].startswith(b'ERR 112 ')
                assert mobile.card_confirmations == previous
                assert scd.command(b'SETDATA '+b'01'*32)[-1] == b'OK'
                scd.send(b'PKSIGN --hash=sha256 OPENPGP.1')
                wait_for(lambda: mobile.card_confirmations >= previous + 2)
                assert len(mobile.card.commands) == before, 'USB confirmation must not open NFC or send a PIN'
            # X without a card cancels the entire operation and cannot be
            # undone by public metadata queries or target refinement.
            mobile.decline_card = True
            previous = mobile.card_confirmations
            with Assuan(a, 'scdaemon') as scd:
                for command in (b'PKSIGN --hash=sha256 OPENPGP.1', b'PKDECRYPT OPENPGP.2'):
                    assert scd.command(b'RESET')[-1] == b'OK'
                    assert scd.command(('SERIALNO --demand='+card['serial']).encode())[-1].startswith(b'ERR 112 ')
                    assert mobile.card_confirmations == previous, 'RESET discovery requested consent'
                    assert scd.command(b'SETDATA '+b'01'*32)[-1] == b'OK'
                    started = time.monotonic()
                    assert scd.command(command)[-1].startswith(b'ERR 99 ')
                    assert time.monotonic() - started < 3
                    assert mobile.card_confirmations > previous, 'new operation did not request consent'
                    previous = mobile.card_confirmations
                    assert scd.command(b'READKEY OPENPGP.1')[-1].startswith(b'ERR')
                    assert scd.command(command)[-1].startswith(b'ERR')
                    assert mobile.card_confirmations == previous, 'canceled operation prompted again'
            assert len(mobile.card.commands) == before
            mobile.decline_card = False
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            mobile.send(action='nfc_capability', available=True); mobile.wait('nfc-capability')
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

            # Reading a second NFC key replaces the one process-local snapshot.
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='start'); mobile.wait('started')
            second_card = dict(card, serial='D2760001240103040005000088880000')
            mobile.card = Card(second_card)
            mobile.send(action='record_nfc', present=True); mobile.wait('recorded')
            with Assuan(a, 'scdaemon') as scd:
                inventory = scd.command(b'GETINFO card_list')
                assert b'S SERIALNO ' + card['serial'].encode() not in inventory, inventory
                assert b'S SERIALNO ' + second_card['serial'].encode() in inventory, inventory
                assert scd.command(b'SWITCHCARD ' + second_card['serial'].encode())[-1] == b'OK'
                assert scd.command(b'SETDATA ' + b'01' * 32)[-1] == b'OK'
                result = scd.command(b'PKSIGN --hash=sha256 OPENPGP.1', lambda _: [b'D 123456', b'END'])
                assert result[-1] == b'OK', result
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='nfc_capability', available=False); mobile.wait('nfc-capability')
            mobile.send(action='usb_presence', present=False); mobile.wait('usb-presence')
            mobile.send(action='start'); mobile.wait('started')
            first_event = len(mobile.operation_events)
            with Assuan(a, 'scdaemon') as scd:
                inventory = scd.command(b'GETINFO card_list')
                assert inventory[-1].startswith(b'ERR 112 '), inventory
            assert ('open', 'Nfc') not in mobile.operation_events[first_event:]
            a.kill_agent()
            mobile.send(action='stop'); mobile.wait('stopped')
            mobile.send(action='clear_nfc'); mobile.wait('nfc-cleared')
            mobile.send(action='nfc_capability', available=True); mobile.wait('nfc-capability')
            mobile.card = Card(card)
            mobile.send(action='start'); mobile.wait('started')
            print('PASS: NFC reread replaces the previous snapshot; unavailable NFC is excluded', flush=True)

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
                mobile.send(action='usb_presence', present=True); mobile.wait('usb-presence')
                a.gpg('--card-status')
                sig = a.gpg('--local-user', efpr, '--detach-sign', data=b'ECC card signing').stdout
                message.write_bytes(b'ECC card signing'); signature.write_bytes(sig)
                a.gpg('--verify', signature, message)
                ciphertext = a.gpg('--trust-model', 'always', '--recipient', efpr, '--encrypt', data=b'ECC card decryption').stdout
                assert a.gpg('--decrypt', data=ciphertext).stdout == b'ECC card decryption'
                print('PASS: real GnuPG mobile %s signing + %s decryption' % (signing, decryption), flush=True)

            # X always cancels the entire operation, with or without USB.
            # A second input device must not override cancellation.
            a.services(pinentry=True); a.mode(delay=2, password='desktop'); a.restart()
            mobile.delay = .05
            for present in (False, True):
                mobile.send(action='usb_presence', present=present); mobile.wait('usb-presence')
                mobile.pin_action = 'cancel_request'
                with Assuan(a, 'pinentry') as pin:
                    result = pin.command(b'GETPIN')
                    assert result[-1].startswith(b'ERR 99 '), result
                    assert not any(line.startswith(b'D ') for line in result)
                    wait_for(a.idle)
                    # Only an explicit new caller command starts a fresh request.
                    mobile.pin_action = None
                    assert pin.command(b'GETPIN')[-1] == b'OK'
                wait_for(a.idle)
            mobile.pin_action = None
            a.mode()
            print('PASS: iOS X with or without USB cancels all input candidates; new requests still work', flush=True)

            # A second desktop pinentry beats a delayed mobile UI and cancels its token.
            a.services(pinentry=True); a.restart(); mobile.delay = 2
            with Assuan(a, 'pinentry') as pin:
                assert pin.command(b'GETPIN')[-1] == b'OK'
            wait_for(lambda: mobile.canceled)
            mobile.send(action='create', name='phone-owned')
            created=mobile.wait('created')
            guest=Device(root,'guest',url); devices.append(guest)
            mobile.send(action='policy'); assert mobile.wait('policy')['allow_creation']
            rejected = guest.cli('channel','join',created['invite'],'--no-wait').stdout.decode().split()[1]
            mobile.send(action='reject', channel=created['channel'], request=rejected); mobile.wait('rejected')
            mobile.send(action='pending', channel=created['channel'])
            assert not mobile.wait('pending')['requests']
            mobile.send(action='invite', channel=created['channel']); fresh=mobile.wait('invitation')
            guest_join=guest.cli('channel','join',fresh['invite'],'--no-wait').stdout.decode().splitlines()
            joined_guest=guest_join[0].split()[1]
            verification=next(line.split()[1] for line in guest_join if line.startswith('verification '))
            mobile.send(action='pending',channel=created['channel']); pending=mobile.wait('pending')['requests']
            assert len(pending)==1 and pending[0]['id']==joined_guest and len(pending[0]['words'].split())==24
            mobile.send(action='approve_verification',channel=created['channel'],request=joined_guest,code=verification); mobile.wait('approved')
            assert json.loads(guest.cli('channel','list','--json').stdout)['channels'][0]['member'] is True
            mobile.send(action='revoke',channel=created['channel'],device=guest.id); mobile.wait('revoked')
            assert json.loads(guest.cli('channel','list','--json').stdout)['channels'][0]['member'] is False
            mobile.send(action='invite',channel=created['channel']); reentry=mobile.wait('invitation')
            new_join=guest.cli('channel','join',reentry['invite'],'--no-wait').stdout.decode().splitlines()
            new_request=new_join[0].split()[1]
            new_code=next(line.split()[1] for line in new_join if line.startswith('verification '))
            mobile.send(action='approve_verification',channel=created['channel'],request=new_request,code=new_code); mobile.wait('approved')
            assert json.loads(guest.cli('channel','list','--json').stdout)['channels'][0]['member'] is True
            mobile.send(action='leave',channel=created['channel']); mobile.wait('left')
            a.cli('channel', 'create', 'withdraw-test')
            withdrawal_invite = a.cli('channel', 'invite', 'withdraw-test').stdout.decode().strip()
            mobile.send(action='join', invite=withdrawal_invite)
            withdrawal = mobile.wait('joined')
            mobile.send(action='pairing_status', channel=withdrawal['channel'], request=withdrawal['request'])
            assert mobile.wait('pairing_status')['state'] == 'Pending'
            mobile.send(action='withdraw', channel=withdrawal['channel'], request=withdrawal['request']); mobile.wait('withdrawn')
            mobile.send(action='pairing_status', channel=withdrawal['channel'], request=withdrawal['request'])
            assert mobile.wait('pairing_status')['state'] == 'Absent'
            assert withdrawal['request'].encode() not in a.cli('channel', 'pending', 'withdraw-test').stdout
            print('PASS: mobile relay policy, request rejection, withdrawal and pairing status', flush=True)
            print('PASS: mobile create/invite, pending verification, QR verification approval, revocation, readmission and leave', flush=True)
            mobile.send(action='stop'); mobile.wait('stopped')
            print('PASS: losing mobile prompt canceled; background stop cancels requests', flush=True)
        finally:
            if mobile: mobile.close()
            for device in devices:
                device.stop(); device.kill_agent()
            server.terminate(); server.wait(timeout=10); log.close()


if __name__ == '__main__':
    main()
