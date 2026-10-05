#!/usr/bin/env python3
"""Deterministic stdio pinentry; never logs entered secrets."""
import json
import os
from pathlib import Path
import sys
import time
from assuan_stdio import emit, esc

base = Path(sys.argv[1])
marker = base / ('pinentry-%s' % os.getpid())
marker.write_text('started')
replayed = []

try:
    emit(b'OK controlled pinentry')
    for raw in sys.stdin.buffer:
        if raw.startswith(b'SETDESC '):
            (base/'pinentry-description.txt').write_bytes(raw)
        command = raw.rstrip(b'\r\n').split(b' ', 1)[0]
        # Opt-in compatibility trace: command/option names only, never values,
        # passwords, inquiry replies or dialog text.
        if command == b'OPTION':
            replayed.append('OPTION ' + raw.rstrip(b'\r\n').partition(b' ')[2].split(b'=', 1)[0].decode())
        elif command.startswith(b'SET'):
            replayed.append(command.decode())
        if command in (b'GETPIN', b'CONFIRM', b'MESSAGE'):
            if (base/'pinentry-record-commands').exists():
                (base/('pinentry-replay-%s.json' % os.getpid())).write_text(json.dumps(replayed))
            mode = json.loads((base / 'pinentry-mode.json').read_text())
            marker.write_text('waiting')
            time.sleep(mode.get('delay', 0))
            if command == b'CONFIRM' and mode.get('confirm_file'):
                answer = Path(mode['confirm_file'])
                while not answer.exists():
                    time.sleep(.01)
                response = answer.read_bytes()
                answer.unlink()
                emit(response)
                marker.write_text('completed')
                continue
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
            if mode.get('fully_cancel'):
                emit(b'D incomplete')
                emit(b'ERR 83886278 operation canceled')
            elif mode.get('cancel'):
                if mode.get('partial_cancel'):
                    emit(b'D incomplete')
                emit(('ERR %d canceled' % mode.get('cancel_code', 83886179)).encode())
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
                    emit(b'D ' + esc(password.encode()))
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
