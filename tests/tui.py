#!/usr/bin/env python3
"""Real PTY lifecycle checks, using only isolated configuration and no relay."""
import fcntl
import os
import pty
import re
import selectors
import signal
import struct
import subprocess
import tempfile
import termios
import time
from pathlib import Path
from integration import Device, CLIENT, SERVER, run, wait_for


def terminal_text(output):
    # Ratatui redraws only changed cells; stripping escapes alone loses letters.
    cells = {}
    row, column = 1, 1
    tokens = re.findall(r'\x1b\[[0-?]*[ -/]*[@-~]|[^\x1b]', output.decode('utf-8', errors='replace'))
    for token in tokens:
        if token.startswith('\x1b['):
            code = token[-1]
            parameters = token[2:-1]
            if code in ('H', 'f'):
                parts = parameters.split(';')
                row = int(parts[0] or 1)
                column = int(parts[1] or 1) if len(parts) > 1 else 1
            elif code == 'J' and parameters in ('2', '3'):
                cells.clear()
        elif token == '\r':
            column = 1
        elif token == '\n':
            row += 1
        elif token.isprintable():
            cells[row, column] = token
            column += 2 if __import__('unicodedata').east_asian_width(token) in ('W', 'F') else 1
    return '\n'.join(''.join(cells.get((r, c), ' ') for c in range(1, 201)) for r in range(1, 61))


def read_until(fd, marker, output, timeout=15):
    end = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        def found():
            if marker.startswith(b'\x1b'):
                return marker in output
            return marker.decode() in terminal_text(output)
        while not found():
            assert time.monotonic() < end, (marker, terminal_text(output))
            if selector.select(.1):
                output += os.read(fd, 65536)
    return output


def check(device, quit_key):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 35, 120, 0, 0))
    process = subprocess.Popen([str(CLIENT), 'tui'], env=dict(device.env, TERM='xterm-256color'), stdin=slave, stdout=slave, stderr=slave)
    try:
        output = read_until(master, b'Overview', b'')
        assert b'\x1b[?1049h' in output
        os.write(master, b'2')
        output = read_until(master, b'Channels', output)
        os.write(master, b'\t')
        output = read_until(master, b'Channels \xc2\xb7 0 *', output)
        os.write(master, b'\t')
        output = read_until(master, b'Details \xc2\xb7 full identities *', output)
        os.write(master, b'\t')
        output = read_until(master, b'Navigation *', output)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 16, 48, 0, 0))
        process.send_signal(signal.SIGWINCH)
        # Navigation, help and filtering must remain responsive while offline.
        os.write(master, b'5?')
        output = read_until(master, b'Help', output)
        os.write(master, b'\x1b')
        time.sleep(.2)
        os.write(master, b'2/unknown\r')
        time.sleep(.2)
        os.write(master, quit_key)
        output = read_until(master, b'\x1b[?1049l', output)
        process.wait(timeout=5)
        assert process.returncode == 0
        assert termios.tcgetattr(slave) == before, 'terminal flags not restored'
        output = read_until(master, b'\x1b[?1049l', output)
        assert b'\x1b[?25h' in output, 'cursor not restored'
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        os.close(master); os.close(slave)


def check_config_conflict(device):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 160, 0, 0))
    process = subprocess.Popen([str(CLIENT), 'tui'], env=dict(device.env, TERM='xterm-256color'), stdin=slave, stdout=slave, stderr=slave)
    try:
        output = read_until(master, b'Relay offline', b'')
        os.write(master, b'5a')
        output = read_until(master, b'Edit local service settings', output)
        os.write(master, b'\r')
        output = read_until(master, b'Edit local settings', output)
        edited = device.config.read_text() + '\n# external edit must survive\n'
        device.config.write_text(edited)
        os.write(master, b'\t' * 5 + b'\r')
        output = read_until(master, b'configuration changed', output)
        assert device.config.read_text() == edited
        # A persistent error modal can arrive after its footer text; Ctrl-C is
        # the global exit action and must restore the terminal from any modal.
        os.write(master, b'\x03')
        read_until(master, b'\x1b[?1049l', output)
        process.wait(timeout=5)
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        os.close(master); os.close(slave)


def check_invitation(root):
    """Generate/export an actual invitation through the PTY, then consume it."""
    config = root / 'relay.toml'
    config.write_text('listen="127.0.0.1:0"\ndatabase="relay.sqlite3"\nallow_client_channel_creation=true\n')
    log_path = root / 'relay.log'
    with log_path.open('w') as log:
        server = subprocess.Popen([str(SERVER), '--config', str(config)], stdout=log, stderr=log)
        process = None
        master, slave = pty.openpty()
        try:
            port = wait_for(lambda: re.search(r'listening on 127.0.0.1:(\d+)', log_path.read_text())).group(1)
            url = 'ws://127.0.0.1:%s/hibiki' % port
            founder, guest = [Device(root, name, url) for name in ('founder', 'guest')]
            founder.cli('channel', 'create', 'PTY invitations')
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 35, 120, 0, 0))
            process = subprocess.Popen([str(CLIENT), 'tui'], env=dict(founder.env, TERM='xterm-256color'), stdin=slave, stdout=slave, stderr=slave)
            output = read_until(master, b'relay online', b'')
            os.write(master, b'2i')
            output = read_until(master, b'One-use invitation', output)
            os.write(master, b'v')
            output = read_until(master, b'Terminal too small for this QR code', output)
            os.write(master, b'e')
            output = read_until(master, b'Export secret (0600)', output)
            png = root / 'invitation.png'
            os.write(master, str(png).encode() + b'\r\r')
            output = read_until(master, b'Secret exported', output)
            assert png.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
            assert png.stat().st_mode & 0o777 == 0o600
            # A second invitation is independently registered. Export its text
            # for a real join and require the consumed invitation to stay spent.
            os.write(master, b'i')
            output = read_until(master, b'One-use invitation', output)
            os.write(master, b'e')
            output = read_until(master, b'Export secret (0600)', output)
            invitation = root / 'invitation.txt'
            os.write(master, str(invitation).encode() + b'\r\r')
            output = read_until(master, b'Secret exported', output)
            text = invitation.read_text()
            assert text.startswith('hibiki-invite-v2:')
            output = read_until(master, b'Secret exported', output)
            joined = guest.cli('channel', 'join', text, '--no-wait').stdout
            assert b'hibiki-verify-v1:' in joined
            check_waiting_verification(guest)
            guest.cli('channel', 'leave', 'PTY invitations')
            guest.cli('channel', 'join', text, '--no-wait', ok=False)
            os.write(master, b'q')
            read_until(master, b'\x1b[?1049l', output)
            process.wait(timeout=5)
            assert process.returncode == 0
        finally:
            if process and process.poll() is None:
                process.kill(); process.wait()
            os.close(master); os.close(slave)
            server.send_signal(signal.SIGINT); server.wait(timeout=10)


def check_waiting_verification(device):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 70, 120, 0, 0))
    process = subprocess.Popen([str(CLIENT), 'tui'], env=dict(device.env, TERM='xterm-256color'), stdin=slave, stdout=slave, stderr=slave)
    try:
        output = read_until(master, b'relay online', b'')
        os.write(master, b'4a')
        output = read_until(master, b'Show verification QR / text', output)
        os.write(master, b'\r')
        output = read_until(master, b'public verification code', output)
        os.write(master, b'v')
        output = read_until(master, b'hibiki-verify-v1:', output)
        os.write(master, b'\x03')
        read_until(master, b'\x1b[?1049l', output)
        process.wait(timeout=5)
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        os.close(master); os.close(slave)


def main():
    run(['cargo', 'build', '--locked', '-p', 'hibiki', '-p', 'hibiki-server'], timeout=600)
    with tempfile.TemporaryDirectory(prefix='hibiki-tui-', dir='/tmp') as directory:
        device = Device(Path(directory), 'terminal', 'ws://127.0.0.1:1/hibiki')
        original = device.config.read_bytes()
        error = device.cli('tui', ok=False)
        assert b'interactive terminal' in error.stderr
        for key in [b'q', b'\x03']:
            check(device, key)
        assert device.config.read_bytes() == original
        check_config_conflict(device)
        device.config.write_text('invalid configuration !!!')
        error = device.cli('status', '--json', ok=False)
        assert device.config.read_text() == 'invalid configuration !!!'
        check_invitation(Path(directory))
    print('PASS: TUI pane focus, invitation creation/export/consumption, unclipped QR, offline navigation, resize and terminal restoration')


if __name__ == '__main__':
    main()
