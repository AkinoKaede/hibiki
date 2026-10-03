#!/usr/bin/env python3
"""Deterministic stdio pinentry; never logs entered secrets."""
import json
import os
from pathlib import Path
import sys
import time

base = Path(sys.argv[1])
marker = base / ('pinentry-%s' % os.getpid())
marker.write_text('started')

def emit(line):
    sys.stdout.buffer.write(line + b'\n')
    sys.stdout.buffer.flush()

def escape(data):
    return data.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')

try:
    emit(b'OK controlled pinentry')
    for raw in sys.stdin.buffer:
        if raw.startswith(b'SETDESC '):
            (base/'pinentry-description.txt').write_bytes(raw)
        command = raw.rstrip(b'\r\n').split(b' ', 1)[0]
        if command in (b'GETPIN', b'CONFIRM', b'MESSAGE'):
            mode = json.loads((base / 'pinentry-mode.json').read_text())
            marker.write_text('waiting')
            time.sleep(mode.get('delay', 0))
            if mode.get('inquiry'):
                emit(b'INQUIRE QUALITY candidate%2Bvalue')
                answer = []
                for line in sys.stdin.buffer:
                    answer.append(line.rstrip(b'\r\n'))
                    if answer[-1] in (b'END', b'CAN'):
                        break
                if answer != [b'D 100', b'END']:
                    emit(b'ERR 1 incorrect inquiry routing')
                    continue
            if command == b'CONFIRM' and not mode.get('confirm'):
                emit(b'ERR 99 canceled confirmation')
                continue
            if mode.get('cancel'):
                emit(b'ERR 83886179 canceled')
            elif mode.get('partial_error'):
                emit(b'D incomplete')
                emit(b'ERR 1 failed')
            else:
                if command == b'GETPIN':
                    password = mode.get('password', '123456')
                    if 'sequence' in mode:
                        counter = base/'pinentry-attempts'
                        attempt = int(counter.read_text()) if counter.exists() else 0
                        password = mode['sequence'][min(attempt,len(mode['sequence'])-1)]
                        counter.write_text(str(attempt+1))
                    emit(b'D ' + escape(password.encode()))
                emit(b'OK')
            marker.write_text('completed')
        elif command == b'BYE':
            emit(b'OK')
            break
        elif command == b'GETINFO':
            emit(b'D 1.3.0')
            emit(b'OK')
        else:
            emit(b'OK')
except BrokenPipeError:
    pass
finally:
    marker.write_text('exited')
