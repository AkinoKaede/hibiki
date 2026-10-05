#!/usr/bin/env python3
"""Test-only OpenPGP card emulator over stdio, using isolated RSA test keys.

No real card is opened. PKCS#1 signing/decryption uses Python integer arithmetic;
GnuPG verifies the output end to end. Never use these operations for real keys.
"""
import json
import os
from pathlib import Path
import sys
import time

base = Path(sys.argv[1])
card = json.loads((base / 'card.json').read_text()) if (base / 'card.json').exists() else {'present': False, 'serial': 'D2760001240100000000000000000000', 'keys': []}
marker = base / ('scdaemon-%s' % os.getpid())
marker.write_text('started')
data = b''
# Opaque stand-in for scdaemon's process-key-wrapped PIN, never an actual PIN.
pin_cache = {}

def emit(line):
    sys.stdout.buffer.write(line + b'\n')
    sys.stdout.buffer.flush()

def esc(data):
    return data.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')

def unesc(data):
    import re
    return re.sub(rb'%([0-9a-fA-F]{2})', lambda m: bytes([int(m[1], 16)]), data)

def send(data):
    for i in range(0, len(data), 300):
        emit(b'D ' + esc(data[i:i+300]))

def atom(data):
    return str(len(data)).encode() + b':' + data

def mpi(value):
    data = value.to_bytes((value.bit_length()+7)//8, 'big')
    return (b'\0' if data[0] & 128 else b'') + data

def pub(key):
    return b'(10:public-key(3:rsa(1:n' + atom(mpi(int(key['n'],16))) + b')(1:e' + atom(mpi(int(key['e'],16))) + b')))'

def selected_key(args):
    name = args.split()[-1]
    for key in card['keys']:
        if name in (key['grip'], key['ref']):
            return key
    return None

def pin(ref):
    if card.get('pin_cache') and ref in pin_cache:
        emit(('INQUIRE PINCACHE_GET 0/openpgp/' + ref).encode())
        chunks = []
        for raw in sys.stdin.buffer:
            line = raw.rstrip(b'\r\n')
            if line in (b'END', b'CAN'): break
            if line.startswith(b'D '): chunks.append(unesc(line[2:]))
        if b''.join(chunks) == pin_cache[ref]:
            with (base/'card-cache-events').open('a') as log: log.write('hit\n')
            return True
    emit(b'INQUIRE NEEDPIN ||Please enter the PIN')
    chunks = []
    for raw in sys.stdin.buffer:
        line = raw.rstrip(b'\r\n')
        if line == b'CAN':
            emit(b'ERR 99 canceled')
            return False
        if line == b'END':
            break
        if line.startswith(b'D '):
            chunks.append(unesc(line[2:]))
    if b''.join(chunks).rstrip(b'\0') != b'123456':
        emit(b'ERR 87 Bad PIN')
        return False
    if card.get('pin_cache'):
        pin_cache[ref] = os.urandom(24).hex().encode()
        emit(b'S PINCACHE_PUT 0/openpgp/' + ref.encode() + b' ' + pin_cache[ref])
        with (base/'card-cache-events').open('a') as log: log.write('put\n')
    return True

def attributes():
    yield 'SERIALNO ' + card['serial']
    yield 'APPTYPE OPENPGP'
    yield 'DISP-NAME HIbiki test card'
    yield 'DISP-LANG en'
    yield 'DISP-SEX 9'
    yield 'CHV-STATUS 1 127 127 127 3 3 3'
    yield 'SIG-COUNTER 0'
    yield 'EXTCAP ki=1 aac=1'
    for i, key in enumerate(card['keys'], 1):
        yield 'KEYPAIRINFO %s %s' % (key['grip'], key['ref'])
        yield 'KEY-FPR %s %s' % (i, key['fingerprint'])
        yield 'KEY-ATTR %s 1 rsa2048' % i
        yield 'KEY-TIME %s 0' % i

try:
    emit(b'OK controlled scdaemon')
    for raw in sys.stdin.buffer:
        text = raw.rstrip(b'\r\n').decode()
        command, _, args = text.partition(' ')
        if (base / 'card.json').exists(): card = json.loads((base / 'card.json').read_text())
        with (base / 'card-commands.log').open('a') as f:
            f.write(command + (' '+args if command in ('SERIALNO','LEARN','READKEY','GETATTR','KEYINFO') else '') + '\n')
        if command == 'SERIALNO':
            time.sleep(card.get('delay', 0))
            demand = next((a[9:] for a in args.split() if a.startswith('--demand=')), None)
            if not card.get('present', True) or (demand and demand != card['serial']):
                emit(b'ERR 100663404 Card not present')
                continue
            emit(('S SERIALNO ' + card['serial']).encode())
        elif command == 'LEARN':
            for attr in attributes():
                emit(('S ' + attr).encode())
        elif command == 'KEYINFO':
            keys = card['keys'] if '--list' in args else [selected_key(args)]
            if keys == [None]:
                emit(b'ERR 27 Not found')
                continue
            for key in keys:
                info = '%s T %s %s %s' % (key['grip'],card['serial'],key['ref'],'s' if key['ref']=='OPENPGP.1' else 'e')
                if '--data' in args:
                    send(info.encode()+b'\n')
                else:
                    emit(('S KEYINFO '+info).encode())
        elif command == 'GETATTR':
            for attr in attributes():
                if attr.startswith(args + ' '):
                    emit(('S ' + attr).encode())
        elif command == 'GETINFO':
            if args == 'version':
                send(b'2.4.0')
            elif args == 'app_list':
                send(b'openpgp:\n')
            elif args == 'card_list':
                emit(('S SERIALNO ' + card['serial']).encode())
        elif command == 'READKEY':
            key = selected_key(args)
            if key is None:
                emit(b'ERR 17 No key')
                continue
            if '--info' in args:
                emit(('S KEYPAIRINFO %s %s' % (key['grip'], key['ref'])).encode())
            send(pub(key))
        elif command == 'SETDATA':
            if args.startswith('--append '):
                data += bytes.fromhex(args[9:])
            else:
                data = bytes.fromhex(args)
        elif command in ('PKSIGN', 'PKDECRYPT'):
            time.sleep(card.get('private_delay', 0))
            key = selected_key(args)
            if key is None:
                emit(b'ERR 17 No key')
                continue
            if not pin("1" if command == "PKSIGN" else "2"):
                continue
            n, d = int(key['n'],16), int(key['d'],16)
            width = (n.bit_length()+7)//8
            if command == 'PKSIGN':
                padded = b'\0\x01' + b'\xff'*(width-len(data)-3) + b'\0' + data
                send(pow(int.from_bytes(padded,'big'),d,n).to_bytes(width,'big'))
            else:
                padded = pow(int.from_bytes(data,'big'),d,n).to_bytes(width,'big')
                assert padded[:2] == b'\0\x02'
                emit(b'S PADDING 0')
                send(padded[padded.index(b'\0',2)+1:])
        elif command in ('RESET','RESTART'):
            data = b''
            if command == 'RESET': pin_cache.clear()
        elif command == 'BYE':
            emit(b'OK')
            break
        elif command not in ('NOP', 'SWITCHAPP', 'SWITCHCARD'):
            emit(b'ERR 60 unsupported')
            continue
        emit(b'OK')
except BrokenPipeError:
    pass
finally:
    marker.write_text('exited')
