#!/usr/bin/env python3
"""Isolated real GnuPG + stdio fixtures. Never opens user keys or real readers."""
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'target' / 'debug'
CLIENT, SERVER = BIN / 'hibiki', BIN / 'hibiki-server'
GPG, GPGCONF = shutil.which('gpg'), shutil.which('gpgconf')
assert GPG and GPGCONF

def run(args, env=None, data=None, ok=True, timeout=40, cwd=None):
    if str(args[0]) == 'git':
        env = {k:v for k,v in (env or os.environ).items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    p = subprocess.run(list(map(str,args)), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env, timeout=timeout, cwd=cwd)
    if ok and p.returncode:
        raise AssertionError('%s failed:\n%s' % (args, p.stderr.decode(errors='replace')))
    if not ok and p.returncode == 0:
        raise AssertionError('%s unexpectedly succeeded' % args)
    return p

def wait_for(predicate, timeout=15):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        value=predicate()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError('condition timed out')

def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False

class Assuan:
    def __init__(self, device, kind):
        self.p = subprocess.Popen([str(BIN/('hibiki-'+kind))],env=device.env,
                                  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        assert self.line().startswith(b'OK')
    def line(self, timeout=15):
        with selectors.DefaultSelector() as sel:
            sel.register(self.p.stdout, selectors.EVENT_READ)
            assert sel.select(timeout), 'Assuan response timeout'
        line = self.p.stdout.readline().rstrip(b'\r\n')
        assert line, 'Assuan disconnected: '+self.p.stderr.read().decode(errors='replace')
        return line
    def send(self, line):
        self.p.stdin.write(line+b'\n');self.p.stdin.flush()
    def result(self, inquiry=None):
        lines=[]
        while True:
            line=self.line();lines.append(line)
            if line.startswith(b'INQUIRE '):
                assert inquiry is not None, line
                for answer in inquiry(line): self.send(answer)
            if line==b'OK' or line.startswith((b'OK ',b'ERR ')):
                return lines
    def command(self, line, inquiry=None):
        self.send(line);return self.result(inquiry)
    def close(self):
        if self.p.poll() is None:
            self.p.terminate()
        self.p.wait(timeout=10)
        self.p.stdin.close();self.p.stdout.close();self.p.stderr.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

class Device:
    def __init__(self, root, name, url):
        self.root=root/name;self.root.mkdir(mode=0o700)
        self.native=self.root/'native';self.native.mkdir(mode=0o700)
        self.env=os.environ.copy()
        for key in list(self.env):
            if key.startswith(('HIBIKI_','GPG_REMOTE_','GNUPG','GPG_AGENT','ASSUAN_')):
                self.env.pop(key)
        for key,folder in [('XDG_CONFIG_HOME','config'),('XDG_DATA_HOME','data'),('XDG_RUNTIME_DIR','run'),('XDG_CACHE_HOME','cache'),('XDG_STATE_HOME','state')]:
            path=self.root/folder;path.mkdir(mode=0o700);self.env[key]=str(path)
        self.env['GNUPGHOME']=str(self.native)
        self.env['RUST_LOG']='hibiki=debug'
        self.id=self.cli('init','--server',url,'--name',name,'--allow-insecure').stdout.decode().split()[1]
        self.config=self.root/'config'/'hibiki'/'client.toml'
        self.env['HIBIKI_CONFIG']=str(self.config)
        self.daemon=None;self.log=None
        for kind in ('pinentry','scdaemon'):
            path=self.root/('test-'+kind)
            path.write_text('#!/bin/sh\nexec %s %s %s "$@"\n' % tuple(shlex.quote(str(v)) for v in (sys.executable, ROOT/'tests'/(kind+'.py'),self.root)))
            path.chmod(0o700)
        self.mode()
    def cli(self,*args,**kw): return run([CLIENT,*args],env=self.env,**kw)
    def gpg(self,*args,**kw): return run([GPG,'--homedir',self.native,*args],env=self.env,**kw)
    def mode(self,**kw):
        mode={'delay':.05,'password':'123456','cancel':False};mode.update(kw)
        (self.root/'pinentry-mode.json').write_text(json.dumps(mode))
    def card(self, value):
        # Providers probe concurrently: publish fixture card changes atomically.
        path = self.root/'card.json.new'
        path.write_text(json.dumps(value)); path.chmod(0o600)
        path.replace(self.root/'card.json')
    def services(self,scdaemon=False,pinentry=False,timeout=8):
        text=self.config.read_text().split('[scdaemon]')[0]
        text=re.sub(r'operation_timeout_seconds = \d+', 'operation_timeout_seconds = %s'%timeout,text)
        for kind,enabled in [('scdaemon',scdaemon),('pinentry',pinentry)]:
            text+='\n[%s]\nenabled = %s\nprogram = %s\n'%(kind,str(enabled).lower(),json.dumps(str(self.root/('test-'+kind))))
        self.config.write_text(text)
    def configure_agent(self,card=True):
        text='pinentry-program %s\nignore-cache-for-signing\ndefault-cache-ttl 0\nmax-cache-ttl 0\n' % (BIN/'hibiki-pinentry')
        if card: text+='scdaemon-program %s\n' % (BIN/'hibiki-scdaemon')
        (self.native/'gpg-agent.conf').write_text(text)
        self.kill_agent()
    def kill_agent(self):
        probe = subprocess.run([str(Path(GPGCONF).with_name('gpg-connect-agent')),
                                '--no-autostart', '--homedir', str(self.native), 'GETINFO pid', '/bye'],
                               env=self.env, capture_output=True, timeout=10)
        match = re.search(rb'^D (\d+)$', probe.stdout, re.M)
        run([GPGCONF,'--homedir',self.native,'--kill','gpg-agent'],env=self.env)
        if match:
            pid = int(match[1])
            # The kill reply acknowledges shutdown before the agent exits. A new
            # GPG command can otherwise connect to the dying agent and get EOF.
            def stopped():
                state = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='],
                                       capture_output=True, text=True, timeout=5).stdout.strip()
                return not state or state.startswith('Z')
            wait_for(stopped)
    def start(self, connected=True):
        self.log_path=self.root/'daemon.log';self.log=self.log_path.open('w')
        self.daemon=subprocess.Popen([str(CLIENT),'daemon'],env=self.env,stdout=self.log,stderr=self.log)
        def ready():
            assert self.daemon.poll() is None,self.log_path.read_text()
            if connected: return 'Hibiki daemon connected' in self.log_path.read_text()
            return b'daemon: running;' in self.cli('status', ok=False).stdout
        wait_for(ready)
    def stop(self):
        if self.daemon and self.daemon.poll() is None:
            self.daemon.send_signal(signal.SIGINT)
            self.daemon.wait(timeout=12)
        if self.log: self.log.close()
    def restart(self): self.stop();self.start()
    def idle(self,kind='pinentry'):
        return all(not alive(int(p.name.rsplit('-',1)[1])) for p in self.root.glob(kind+'-[0-9]*'))
    def waiting(self): return any(p.read_text()=='waiting' and alive(int(p.name.rsplit('-',1)[1])) for p in self.root.glob('pinentry-[0-9]*'))

class SocketAssuan(Assuan):
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(15)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rwb', buffering=0)
        assert self.line().startswith(b'OK')
    def line(self, timeout=15):
        line = self.stream.readline().rstrip(b'\r\n')
        assert line, 'Assuan socket disconnected'
        return line
    def send(self, line): self.stream.write(line+b'\n')
    def close(self): self.stream.close(); self.socket.close()

def concurrent_agent_sessions(device):
    device.configure_agent()
    connect = Path(GPGCONF).with_name('gpg-connect-agent')
    run([connect, '--homedir', device.native, '/bye'], env=device.env)
    path = run([GPGCONF, '--homedir', device.native, '--list-dirs', 'agent-socket'],
               env=device.env).stdout.decode().strip()
    with SocketAssuan(path) as first, SocketAssuan(path) as second:
        assert b'D 2.4.0' in first.command(b'SCD GETINFO version')
        # Keep the first agent session open so its primary scdaemon connection
        # cannot be reused. GnuPG must open the advertised secondary socket.
        reply = second.command(b'SCD GETINFO version')
        assert b'D 2.4.0' in reply, reply
        advertised = first.command(b'SCD GETINFO socket_name')
        socket_path = Path(next(line[2:].decode() for line in advertised if line.startswith(b'D ')))
        assert socket_path.is_socket()
        assert socket_path.stat().st_mode & 0o777 == 0o600
        assert socket_path.parent.stat().st_mode & 0o777 == 0o700
        assert first.command(b'SCD NOP')[-1] == b'OK'
        assert second.command(b'SCD NOP')[-1] == b'OK'
        # Eager candidate pools retain their card leases. A later session must
        # not steal the child from either existing adapter session.
        busy = device.gpg('--card-status', ok=False)
        assert b'not available' in busy.stderr
    with SocketAssuan(socket_path) as extra:
        assert b'D 2.4.0' in extra.command(b'GETINFO version')
        device.kill_agent()
        assert extra.stream.readline() == b'', 'secondary connection outlived the primary pipe'
    wait_for(lambda: not socket_path.parent.exists())

def secret_rsa_packets(data):
    result=[];offset=0
    while offset<len(data):
        head=data[offset];offset+=1
        if head&64:
            tag=head&63;n=data[offset];offset+=1
            if n<192: size=n
            elif n<224: size=(n-192)*256+data[offset]+192;offset+=1
            elif n==255: size=int.from_bytes(data[offset:offset+4],'big');offset+=4
            else: raise AssertionError('partial packet unexpected')
        else:
            tag=(head>>2)&15;length=1<<(head&3)
            size=int.from_bytes(data[offset:offset+length],'big');offset+=length
        packet=data[offset:offset+size];offset+=size
        if tag not in (5,7): continue
        assert packet[0]==4 and packet[5]==1
        pos=6
        def mpi():
            nonlocal pos
            size=(int.from_bytes(packet[pos:pos+2],'big')+7)//8;pos+=2
            value=packet[pos:pos+size];pos+=size
            return value.hex()
        n,e=mpi(),mpi();assert packet[pos]==0;pos+=1
        result.append({'n':n,'e':e,'d':mpi()})
    return result

def make_card(device, algorithm="rsa2048"):
    device.gpg('--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','Card Test <card@example.test>',algorithm,'sign','0')
    listing=device.gpg('--with-colons','--with-keygrip','--list-secret-keys').stdout.decode()
    fpr=next(l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:'))
    device.gpg('--batch','--pinentry-mode','loopback','--passphrase','','--quick-add-key',fpr,algorithm,'encr','0')
    listing=device.gpg('--with-colons','--with-keygrip','--list-secret-keys').stdout.decode().splitlines()
    fingerprints=[l.split(':')[9] for l in listing if l.startswith('fpr:')]
    grips=[l.split(':')[9] for l in listing if l.startswith('grp:')]
    keys=secret_rsa_packets(device.gpg('--batch','--pinentry-mode','loopback','--passphrase','','--export-secret-keys',fpr).stdout)
    for i,key in enumerate(keys): key.update(fingerprint=fingerprints[i],grip=grips[i],ref='OPENPGP.%s'%(i+1))
    card={'serial':'D2760001240103040005000012340000','keys':keys}
    device.card(card);(device.root/'card.json').chmod(0o600)
    return fpr,device.gpg('--export',fpr).stdout,card

def pinentry_compatibility(requester, provider):
    """Exercise replay through the adapter, using only synthetic dialog text."""
    record = provider.root/'pinentry-record-commands'
    record.touch()
    def dialog(pe, command):
        before = set(provider.root.glob('pinentry-replay-*.json'))
        answer = pe.command(command)
        paths = wait_for(lambda: set(provider.root.glob('pinentry-replay-*.json')) - before)
        assert len(paths) == 1, paths
        replay = json.loads(paths.pop().read_text())
        if requester is not provider:
            # The native provider initializes its own terminal before replaying
            # requester settings; these are not forwarded remote TTY options.
            native = ['OPTION '+key for key, env in [('ttyname', 'GPG_TTY'), ('ttytype', 'TERM')]
                      if env in provider.env]
            assert replay[:len(native)] == native, replay
            replay = replay[len(native):]
        wait_for(provider.idle)
        return answer, replay
    try:
        provider.mode(confirm=True, delay=.01)
        with Assuan(requester, 'pinentry') as pe:
            assert pe.command(b'OPTION pinentry-user-data=test')[0].startswith(b'ERR 174 ')
            for line in [b'OPTION ttyname=/dev/test-compatibility', b'OPTION default-ok=Proceed',
                         b'OPTION constraints-enforce', b'SETTIMEOUT 5', b'SETDESC Temporary',
                         b'OPTION formatted-passphrase', b'OPTION formatted-passphrase-hint=Temporary',
                         b'SETREPEAT Again', b'SETQUALITYBAR Quality', b'SETKEYINFO test']:
                assert pe.command(line) == [b'OK']
            assert pe.command(b'RESET') == [b'OK']
            answer, replay = dialog(pe, b'GETPIN')
            assert answer[-1] == b'OK'
            expected = {'OPTION default-ok', 'OPTION constraints-enforce', 'SETTIMEOUT'}
            if requester is provider: expected.add('OPTION ttyname')
            assert set(replay) == expected, replay

        for command in [b'GETPIN', b'CONFIRM', b'MESSAGE']:
            for mode in [{}, {'cancel': True}, {'partial_error': True}]:
                provider.mode(confirm=True, delay=.01, **mode)
                with Assuan(requester, 'pinentry') as pe:
                    for line in [b'SETERROR Retry', b'SETREPEAT Again', b'SETQUALITYBAR Quality',
                                 b'SETREPEATERROR Mismatch', b'SETQUALITYBAR_TT Hint', b'SETDESC Persistent']:
                        assert pe.command(line) == [b'OK']
                    answer, replay = dialog(pe, command)
                    assert { 'SETERROR', 'SETREPEAT', 'SETQUALITYBAR' }.issubset(replay), replay
                    assert answer[-1].startswith(b'ERR' if mode else b'OK'), answer
                    provider.mode(confirm=True, delay=.01)
                    answer, replay = dialog(pe, b'GETPIN')
                    assert answer[-1] == b'OK'
                    expected = {'SETREPEATERROR', 'SETQUALITYBAR_TT', 'SETDESC'}
                    if command != b'GETPIN': expected.add('SETREPEAT')
                    assert set(replay) == expected, (command, mode, replay)
                    if command != b'GETPIN':
                        _, replay = dialog(pe, b'GETPIN')
                        assert 'SETREPEAT' not in replay, replay
    finally:
        record.unlink()
        provider.mode()


def missing_card_prompt(requester, provider, input_device, card, args, data, cancel=False):
    """Exercise gpg-agent's own numbered CONFIRM, including an offline card peer."""
    answer = input_device.root/'confirm-answer'
    description = input_device.root/'pinentry-description.txt'
    count = lambda: len(list(input_device.root.glob('pinentry-[0-9]*')))
    def confirm(response):
        pending = answer.with_suffix('.new')
        pending.write_bytes(response)
        pending.replace(answer)
    def wait_prompt(previous):
        wait_for(lambda: count() > previous and input_device.waiting() and description.exists()
                 and b'Please insert the card with serial number' in description.read_bytes(), timeout=3)
        assert b'0005 00001234' in description.read_bytes(), description.read_bytes()
        return count()
    provider.card(dict(card, present=False))
    if cancel: provider.stop()
    input_device.mode(confirm_file=str(answer))
    previous = count()
    command = 'PKDECRYPT' if '--decrypt' in args else 'PKSIGN'
    executions = lambda: (provider.root/'card-commands.log').read_text().splitlines().count(command)
    before = executions()
    process = None
    try:
        with tempfile.TemporaryFile() as source:
            source.write(data); source.seek(0)
            process = subprocess.Popen([GPG, '--homedir', str(requester.native), *args], env=requester.env,
                                       stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            previous = wait_prompt(previous)
            if cancel:
                confirm(b'ERR 99 canceled')
            else:
                confirm(b'OK')  # Confirming without the card must prompt again.
                previous = wait_prompt(previous)
                provider.card(dict(card, serial='D2760001240103040005000099990000', keys=[]))
                confirm(b'OK')  # A different card cannot satisfy the key lookup.
                wait_prompt(previous)
                assert executions() == before
                provider.card(card)
                confirm(b'OK')
            output, error = process.communicate(timeout=15)
            if cancel:
                assert process.returncode != 0 and b'cancel' in error.lower(), error
                assert executions() == before
            else:
                assert process.returncode == 0, error
                assert executions() == before + 1, 'private operation was retried'
            return output
    finally:
        if process and process.poll() is None:
            process.kill(); process.communicate()
        answer.unlink(missing_ok=True)
        provider.card(card)
        if cancel: provider.start()
        input_device.mode()


def test_all():
    with tempfile.TemporaryDirectory(prefix='hi-',dir='/tmp') as temp:
        root=Path(temp);server_data=root/'server';server_data.mkdir(mode=0o700)
        config=server_data/'server.toml';config.write_text('listen = "127.0.0.1:0"\ndatabase = "hibiki.sqlite3"\n')
        server_log=server_data/'server.log';log=server_log.open('w')
        server=subprocess.Popen([str(SERVER),'--config',str(config)],stdout=log,stderr=log)
        devices=[]
        try:
            def listening():
                assert server.poll() is None,server_log.read_text()
                return re.search(r'listening on 127.0.0.1:(\d+)',server_log.read_text())
            port=wait_for(listening).group(1);url='ws://127.0.0.1:%s/hibiki'%port
            a,b,c=[Device(root,name,url) for name in ('a','b','c')];devices=[a,b,c]
            a.cli('channel','create','forbidden',ok=False)
            created=run([SERVER,'--config',config,'channel','create','test','--server',url]).stdout.decode().splitlines()
            bootstrap=created[1].split()[1]
            a.cli('channel','join',bootstrap)
            b.cli('channel','join',bootstrap,ok=False)
            invite=a.cli('channel','invite','test').stdout.decode().strip()
            # Removing a request terminates the waiting CLI without admitting it.
            invite = a.cli('channel', 'invite', 'test').stdout.decode().strip()
            waiting = subprocess.Popen([str(CLIENT), 'channel', 'join', invite],
                                       env=b.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                request = waiting.stdout.readline().decode().split()[1]
                c_invite = a.cli('channel', 'invite', 'test').stdout.decode().strip()
                c.cli('channel', 'join', c_invite, '--no-wait')
                c.cli('channel', 'leave', 'test')
                assert request.encode() in a.cli('channel', 'pending', 'test').stdout
                a.cli('channel', 'reject', 'test', request)
                _, error = waiting.communicate(timeout=10)
                assert waiting.returncode != 0 and b'rejected, withdrawn or invalidated' in error
                assert request.encode() not in a.cli('channel', 'pending', 'test').stdout
            finally:
                if waiting.poll() is None: waiting.kill(); waiting.wait()
            invite = a.cli('channel', 'invite', 'test').stdout.decode().strip()
            waiting = subprocess.Popen([str(CLIENT), 'channel', 'join', invite],
                                       env=b.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                request = waiting.stdout.readline().decode().split()[1]
                second = b.cli('channel', 'join', invite, '--no-wait').stdout.decode().split()[1]
                assert request == second  # Identical retries reuse the signed request and consumed key.
                b.cli('channel', 'leave', 'test')
                _, error = waiting.communicate(timeout=10)
                assert waiting.returncode != 0 and b'rejected, withdrawn or invalidated' in error
                assert not json.loads(a.cli('channel', 'pending', 'test', '--json').stdout)['requests']
                for removed in (request, second):
                    a.cli('channel', 'approve', 'test', removed, data=b'y\n', ok=False)
                b.cli('channel', 'leave', 'test')
            finally:
                if waiting.poll() is None: waiting.kill(); waiting.wait()
            print('PASS: leave cancels all own pending requests and ends waiting admission', flush=True)
            for member,approver in [(b,a),(c,b)]:
                invite=approver.cli('channel','invite','test').stdout.decode().strip()
                joined=member.cli('channel','join',invite,'--no-wait')
                request=joined.stdout.decode().split()[1]
                approver.cli('channel','approve','test',request,data=b'\n')
                assert request.encode() in approver.cli('channel','pending','test').stdout
                approver.cli('channel','approve','test',request[:5],data=b'y\n',ok=False)
                approver.cli('channel','approve','test',request[:6],data=b'y\n')
                member.cli('channel','list')
            b.cli('use', 'test')
            b.cli('channel', 'leave', 'test')
            assert 'default_channel' not in b.config.read_text()
            assert json.loads(b.cli('channel', 'list', '--json').stdout)['channels'][0]['member'] is False
            assert json.loads(a.cli('channel', 'list', '--json').stdout)['channels'][0]['member'] is True
            b.cli('channel', 'leave', 'test')
            invite = a.cli('channel', 'invite', 'test').stdout.decode().strip()
            request = b.cli('channel', 'join', invite, '--no-wait').stdout.decode().split()[1]
            a.cli('channel', 'approve', 'test', request, data=b'y\n')
            assert json.loads(b.cli('channel', 'list', '--json').stdout)['channels'][0]['member'] is True
            print('PASS: the same leave command exits membership, clears the default and permits rejoining', flush=True)
            for d in devices: d.cli('channel','list');d.cli('use','test')
            fpr,public,card=make_card(b)
            a.gpg('--import',data=public)
            a.services();b.services(scdaemon=True,pinentry=True);c.services(pinentry=True)
            for d in devices: d.start()
            assert b'daemon: running; relay: connected' in a.cli('status').stdout
            assert b'client channel creation: false' in a.cli('doctor').stdout
            assert b'hibiki use NAME' in a.cli('setup').stderr
            print('PASS: fresh Hibiki pairing, server-only creation and independent services',flush=True)

            channel_id = json.loads(a.cli('channel', 'list', '--json').stdout)['channels'][0]['id']
            assert json.loads(a.cli('channel', 'pending', channel_id[:6], '--json').stdout)['channel']['id'] == channel_id
            a.cli('use', channel_id[:6])
            a.cli('channel', 'pending', channel_id[:5], '--json', ok=False)
            # Root -> b -> c: descendants cannot revoke ancestors or siblings.
            b.cli('channel', 'revoke', 'test', a.id[:6], ok=False)
            c.cli('channel', 'revoke', 'test', b.id[:6], ok=False)
            a_members = json.loads(a.cli('device', 'list', '--json').stdout)['channels'][0]['devices']
            assert next(d for d in a_members if d['id'] == c.id)['can_revoke']
            b_members = json.loads(b.cli('device', 'list', '--json').stdout)['channels'][0]['devices']
            assert not next(d for d in b_members if d['id'] == a.id)['can_revoke']
            assert next(d for d in b_members if d['id'] == c.id)['approved_by'] == b.id
            # Ping has its own encrypted session and cannot open native services.
            before_children = {d.id: len(list(d.root.glob('scdaemon-[0-9]*'))) + len(list(d.root.glob('pinentry-[0-9]*'))) for d in devices}
            report = json.loads(b.cli('ping', a.id[:6], '--channel', 'test', '--count', '4', '--json').stdout)
            assert report['schema_version'] == 1 and report['ping']['peer'] == a.id
            assert len(report['ping']['round_trips_micros']) == 4
            assert all(value is not None and value > 0 for value in report['ping']['round_trips_micros'])
            assert before_children == {d.id: len(list(d.root.glob('scdaemon-[0-9]*'))) + len(list(d.root.glob('pinentry-[0-9]*'))) for d in devices}
            b.cli('device', 'ping', b.id, '--channel', 'test', ok=False)
            b.cli('device', 'ping', a.id, '--channel', 'test', '--count', '0', ok=False)
            print('PASS: encrypted peer Ping with target services disabled opens no native process', flush=True)

            # Freeze relay replies: local startup, results and selected-card commands
            # must not depend on queue registration, peer discovery or completion ACKs.
            a.services(scdaemon=True,pinentry=True);a.mode(password='local fast',delay=.01);a.restart()
            a.card(card)
            server.send_signal(signal.SIGSTOP)
            try:
                for cold in (False, True):
                    if cold:
                        a.stop();a.start(connected=False)
                    started=time.monotonic()
                    with Assuan(a,'pinentry') as pe:
                        assert b'D local fast' in pe.command(b'GETPIN')
                        assert pe.command(b'MESSAGE')[-1]==b'OK'
                    with Assuan(a,'scdaemon') as sc:
                        assert sc.command(b'GETINFO cmd_has_option SERIALNO all') == [b'OK']
                        assert sc.command(b'GETINFO cmd_has_option SERIALNO unknown')[0].startswith(b'ERR 256 ')
                        assert sc.command(b'GETINFO cmd_has_option')[0].startswith(b'ERR 128 ')
                        assert sc.command(b'GETINFO cmd_has_option SERIALNO')[0].startswith(b'ERR 128 ')
                        assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
                        assert sc.command(b'SETDATA '+b'00'*32)[-1]==b'OK'
                        assert sc.command(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode(),
                                          lambda _: [b'D 123456',b'END'])[-1]==b'OK'
                        assert sc.command(b'RESET')[-1] == b'OK'
                        assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                        assert sc.command(b'SETDATA '+b'11'*32)[-1] == b'OK'
                        assert sc.command(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode(), lambda _: [b'D 123456',b'END'])[-1] == b'OK'
                        key = card['keys'][1]
                        width = (int(key['n'], 16).bit_length()+7)//8
                        clear = b'local offline secret'
                        padded = b'\x00\x02' + b'\x55'*(width-len(clear)-3) + b'\x00' + clear
                        encrypted = pow(int.from_bytes(padded, 'big'), int(key['e'], 16), int(key['n'], 16)).to_bytes(width,'big')
                        assert sc.command(b'SETDATA '+encrypted.hex().encode())[-1] == b'OK'
                        result = sc.command(('PKDECRYPT '+key['grip']).encode(), lambda _: [b'D 123456',b'END'])
                        assert result[-1] == b'OK' and any(clear in line for line in result)
                    assert time.monotonic()-started < 3, 'local service waited for stalled relay'
                    wait_for(lambda:a.idle() and a.idle('scdaemon'))
                a.stop()
            finally:
                server.send_signal(signal.SIGCONT)
            # Requests whose registration was in flight must not appear on peers later.
            counts=[len(list(d.root.glob('pinentry-[0-9]*'))) for d in (b,c)]
            a.services();a.start()
            time.sleep(.5)
            assert counts==[len(list(d.root.glob('pinentry-[0-9]*'))) for d in (b,c)]
            print('PASS: local input and signing bypass stalled relay, including cold daemon startup',flush=True)

            # Discovery is silent even when every enabled provider has no card.
            a.services(scdaemon=True); a.mode(delay=10); a.restart()
            b.services(scdaemon=True); b.mode(delay=10); b.restart()
            for device in (a,b): device.card(dict(card,present=False))
            wait_for(lambda: a.idle() and b.idle())
            prompts = [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)]
            with Assuan(a, 'scdaemon') as sc:
                wait_for(lambda: not a.idle('scdaemon') and not b.idle('scdaemon'))
                children = [len(list(d.root.glob('scdaemon-[0-9]*'))) for d in (a,b)]
                for command in [b'SERIALNO', ('SERIALNO --demand='+card['serial']).encode()]:
                    started = time.monotonic()
                    assert sc.command(command) == [b'ERR 100663408 Card not present']
                    assert time.monotonic() - started < 3, 'no-card discovery waited for insertion'
                assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)], 'discovery created insertion prompts'
                assert a.idle() and b.idle()
                a.card(card)
                assert sc.command(b'SERIALNO')[-1] == b'OK'
                for command in [b'READKEY OPENPGP.1', ('SWITCHCARD '+card['serial']).encode(), b'GETATTR SERIALNO']:
                    assert sc.command(command)[-1] == b'OK'
                assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)]
                a.card(dict(card, present=False))
                assert sc.command(b'SETDATA '+b'00'*32)[-1] == b'OK'
                sc.send(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode())
                wait_for(lambda: a.waiting() and b.waiting())
                prompts = [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)]
                time.sleep(1)
                assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)], 'polling recreated unanswered prompts'
                assert a.waiting() and b.waiting()
                a.card(card)
                assert sc.result(lambda _: [b'D 123456',b'END'])[-1] == b'OK'
                wait_for(lambda: a.idle() and b.idle())
                assert not a.idle('scdaemon') and not b.idle('scdaemon'), 'losing candidate process was closed'
                assert children == [len(list(d.root.glob('scdaemon-[0-9]*'))) for d in (a,b)]
                assert sc.command(b'RESET')[-1] == b'OK'
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                assert children == [len(list(d.root.glob('scdaemon-[0-9]*'))) for d in (a,b)]
                assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)], 'RESET discovery recreated insertion prompts'
            wait_for(lambda: a.idle('scdaemon') and b.idle('scdaemon'))
            # Canceling either Mac's insertion dialog terminates private preparation.
            for cancelling in (a, b):
                for device in (a, b):
                    device.card(dict(card, present=False))
                    device.mode(delay=.1 if device is cancelling else 10,
                                cancel=device is cancelling)
                started = time.monotonic()
                a.card(card)
                with Assuan(a, 'scdaemon') as sc:
                    assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                    a.card(dict(card, present=False))
                    assert sc.command(b'SETDATA '+b'00'*32)[-1] == b'OK'
                    result = sc.command(b'PKSIGN --hash=sha256 OPENPGP.1')
                    assert result[-1].startswith(b'ERR 99 '), result
                    assert time.monotonic() - started < 3, 'insertion Cancel waited for timeout'
                    assert sc.command(b'PKSIGN --hash=sha256 OPENPGP.1')[-1].startswith(b'ERR')
                wait_for(lambda: a.idle() and b.idle())
            a.mode(delay=10); b.mode(delay=10)
            print('PASS: local or remote Mac insertion Cancel ends private preparation without a key', flush=True)
            # The requester stays cardless while the target card arrives remotely.
            for device in (a,b): device.card(dict(card,present=False))
            prompts = [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)]
            with Assuan(a, 'scdaemon') as sc:
                assert sc.command(('SERIALNO --demand='+card['serial']).encode()) == [b'ERR 100663408 Card not present']
                assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)], 'targeted discovery created insertion prompts'
                b.card(card)
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                b.card(dict(card, present=False))
                assert sc.command(b'SETDATA '+b'00'*32)[-1] == b'OK'
                sc.send(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode())
                wait_for(lambda: a.waiting() and b.waiting())
                b.card(card)
                assert sc.result(lambda _: [b'D 123456',b'END'])[-1] == b'OK'
                wait_for(lambda: a.idle() and b.idle())
            wait_for(lambda: a.idle('scdaemon') and b.idle('scdaemon'))

            # A command timeout must also close prompts before the caller disconnects.
            b.card(dict(card,present=False))
            a.services(scdaemon=True,timeout=2); a.restart()
            a.card(card)
            with Assuan(a, 'scdaemon') as sc:
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK'
                a.card(dict(card, present=False))
                sc.send(b'PKSIGN --hash=sha256 OPENPGP.1')
                wait_for(lambda: a.waiting() and b.waiting())
                assert sc.result()[-1].startswith(b'ERR')
                wait_for(lambda: a.idle() and b.idle())
            wait_for(lambda: a.idle('scdaemon') and b.idle('scdaemon'))
            b.card(card)
            a.services(); a.restart(); b.services(scdaemon=True,pinentry=True); b.mode(); b.restart()
            print('PASS: discovery stays silent; private preparation waits for local/remote cards; winners and timeouts close prompts; RESET retains processes', flush=True)

            concurrent_agent_sessions(a)
            print('PASS: simultaneous GnuPG clients use independent scdaemon connections', flush=True)

            # Queue metadata survives a relay restart; only a live caller resumes it.
            a.services(timeout=20);a.restart();b.stop();c.stop()
            def queued():
                with sqlite3.connect(server_data/'hibiki.sqlite3') as db:
                    return db.execute('SELECT count(*) FROM operations WHERE active=1 AND deadline>?', (int(time.time()),)).fetchone()[0]
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(queued)
            server.terminate();server.wait(timeout=10)
            config.write_text(config.read_text().replace('127.0.0.1:0','127.0.0.1:'+port))
            server=subprocess.Popen([str(SERVER),'--config',str(config)],stdout=log,stderr=log)
            wait_for(lambda:a.log_path.read_text().count('Hibiki daemon connected')>=2,timeout=15)
            b.start();assert pe.result()[-1]==b'OK';pe.close()
            count=len(list(c.root.glob('pinentry-[0-9]*')))
            c.start();time.sleep(.5)
            assert count==len(list(c.root.glob('pinentry-[0-9]*'))), 'completed operation replayed on late peer'
            print('PASS: offline PIN queue survives relay restart; completed operation never reaches late peer',flush=True)

            b.stop();c.stop()
            counts=[len(list(d.root.glob('pinentry-[0-9]*'))) for d in (b,c)]
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(queued);pe.close();wait_for(lambda:not queued())
            b.start();c.start();time.sleep(.5)
            assert counts==[len(list(d.root.glob('pinentry-[0-9]*'))) for d in (b,c)], 'abandoned queued request replayed'
            print('PASS: caller exit cancels queued requests before devices return',flush=True)

            b.stop()
            with Assuan(a,'scdaemon') as sc:
                started = time.monotonic()
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1].startswith(b'ERR')
                assert time.monotonic() - started < 3 and not queued()
                b.start()
                wait_for(lambda: sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK')
                assert sc.command(b'SETDATA '+b'00'*32)[-1]==b'OK'
                count=b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN')
                b.stop()
                started = time.monotonic()
                assert sc.command(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode())[-1].startswith(b'ERR')
                assert time.monotonic() - started < 3
                assert b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN') == count
                b.start()
                assert sc.command(b'RESET')[-1] == b'OK'
                wait_for(lambda: sc.command(('SERIALNO --demand='+card['serial']).encode())[-1] == b'OK')
                assert sc.command(b'SETDATA '+b'00'*32)[-1] == b'OK'
                assert sc.command(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode(), lambda _: [b'D 123456',b'END'])[-1] == b'OK'
                assert b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN')==count+1
            print('PASS: offline devices end discovery/preparation promptly; an explicit new request after reconnect signs once',flush=True)

            # Once execution has been claimed, a lost response must never repeat it.
            delayed=dict(card,private_delay=4);b.card(delayed)
            with Assuan(a,'scdaemon') as sc:
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
                assert sc.command(b'SETDATA '+b'00'*32)[-1]==b'OK'
                count=b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN')
                sc.send(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode())
                wait_for(lambda:b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN')==count+1)
                b.stop();result=sc.result()
                assert result[-1].startswith(b'ERR') and b'execution result unknown' in result[-1], result
                b.card(card);b.start();time.sleep(.5)
                assert b.root.joinpath('card-commands.log').read_text().splitlines().count('PKSIGN')==count+1, 'unknown signature replayed'
            print('PASS: lost private-operation result reports unknown and never repeats execution',flush=True)
            a.services();a.restart()

            for code in (99, 83886179):
                for command in (b'GETPIN', b'CONFIRM', b'MESSAGE'):
                    b.mode(delay=.05, confirm=True, cancel=True, cancel_code=code, partial_cancel=True)
                    c.mode(delay=.6, confirm=True, password='remote answer')
                    with Assuan(a,'pinentry') as pe:
                        assert pe.command(b'SETDESC Test remote input')[-1]==b'OK'
                        answer=pe.command(command)
                        assert answer == [('ERR %d canceled' % code).encode()], answer
                        wait_for(lambda: all(d.idle() for d in devices))
                        # A new caller command is a new race, never an automatic retry.
                        b.mode(delay=.01, password='new request')
                        assert pe.command(b'GETPIN') == [b'D new request', b'OK']
                    wait_for(lambda: all(d.idle() for d in devices))
            print('PASS: requester with both services disabled, single cancellation terminates all peers',flush=True)

            b.mode(fully_cancel=True,delay=.05);c.mode(password='must not win',delay=3)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'GETPIN') == [b'ERR 83886278 operation canceled']
            wait_for(lambda: all(d.idle() for d in devices))
            a.services(pinentry=True);a.mode(fully_cancel=True,delay=.01);a.restart()
            b.mode(delay=3)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'GETPIN') == [b'ERR 83886278 operation canceled']
            wait_for(lambda: all(d.idle() for d in devices))
            a.services();a.restart()
            print('PASS: explicit whole-operation cancellation stops local/remote races without leaking partial input',flush=True)

            b.mode(partial_error=True);c.mode(password='complete',delay=.2)
            with Assuan(a,'pinentry') as pe: assert b'D complete' in pe.command(b'GETPIN')
            b.mode(inquiry=True,password='one',delay=.05);c.mode(inquiry=True,password='two',delay=.05)
            seen=[]
            with Assuan(a,'pinentry') as pe:
                def inquiry(line): seen.append(line);return [b'D 100',b'END']
                answer=pe.command(b'GETPIN',inquiry)
                assert answer[-1]==b'OK' and seen
            wait_for(lambda: all(d.idle() for d in devices))
            print('PASS: partial failures cannot win and concurrent inquiries return to their originating candidate',flush=True)

            # A local input participates alongside remote providers.
            a.services(pinentry=True);a.mode(password='local',delay=.01);a.restart()
            b.mode(delay=2);c.mode(delay=2)
            with Assuan(a,'pinentry') as pe: assert b'D local' in pe.command(b'GETPIN')
            wait_for(lambda: all(d.idle() for d in devices))
            a.mode(cancel=True,delay=.01);c.mode(password='remote after local cancel',delay=.2)
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN') == [b'ERR 83886179 canceled']
            a.mode(delay=3);c.mode(password='remote wins',delay=.05)
            with Assuan(a,'pinentry') as pe: assert b'D remote wins' in pe.command(b'GETPIN')
            wait_for(lambda: all(d.idle() for d in devices))
            a.services();a.restart();b.mode(cancel=True);c.mode(cancel=True)
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN')==[b'ERR 83886179 canceled']
            print('PASS: local participation, all-cancel and losing process cleanup',flush=True)

            b.mode(confirm=True);c.mode(confirm=True)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'SETDESC Confirm remote operation')[-1]==b'OK'
                assert pe.command(b'CONFIRM')==[b'OK']
                assert pe.command(b'MESSAGE')==[b'OK']
            wait_for(lambda: all(d.idle() for d in devices))
            print('PASS: remote confirmation and message dialogs complete without password data',flush=True)

            # B supplies only the card; C supplies PINs. Cancel is no longer a way to opt out.
            b.services(scdaemon=True);b.mode(confirm=True);b.restart()
            pinentry_compatibility(a, c)
            print('PASS: remote pinentry preserves RESET options and consumes one-shot settings on success/cancel/failure', flush=True)
            c.mode(password='123456',delay=.1)
            a.configure_agent()
            # The agent tolerates UNKNOWN_OPTION for this optional extension.
            result = run(['gpg-connect-agent', '--homedir', a.native,
                          'OPTION putenv=PINENTRY_USER_DATA=compatibility-test',
                          'GET_PASSPHRASE --data compatibility-cache X Prompt Description',
                          '/bye'], env=a.env)
            assert b'D 123456' in result.stdout and b'ERR ' not in result.stdout, result.stdout
            a.kill_agent()
            print('PASS: real gpg-agent accepts an unsupported PINENTRY_USER_DATA option', flush=True)
            # The requester participates with both services enabled but no local card.
            a.services(scdaemon=True, pinentry=True); a.mode(delay=10); a.card(dict(card, present=False)); a.restart()
            prompts = [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)]
            status=a.gpg('--card-status')
            assert b'00001234' in status.stdout or b'Hibiki test card' in status.stdout,status.stdout
            assert prompts == [set(d.root.glob('pinentry-[0-9]*')) for d in (a,b)], 'real GnuPG card discovery created insertion prompts'
            a.gpg('--batch','--local-user',fpr,'--armor','--detach-sign',data=b'card message')
            signed=a.gpg('--batch','--local-user',fpr,'--detach-sign',data=b'card message').stdout
            message=root/'message';message.write_bytes(b'card message');signature=root/'signature';signature.write_bytes(signed)
            a.gpg('--verify',signature,message)
            cipher=a.gpg('--batch','--trust-model','always','--recipient',fpr,'--encrypt',data=b'card secret').stdout
            plain=a.gpg('--batch','--decrypt',data=cipher).stdout
            assert plain==b'card secret',plain
            git=root/'git';git.mkdir()
            run(['git','init',git]);run(['git','config','user.name','Test'],cwd=git);run(['git','config','user.email','test@example.test'],cwd=git)
            run(['git','config','gpg.program',GPG],cwd=git);run(['git','config','user.signingkey',fpr],cwd=git)
            run(['git','commit','--allow-empty','-S','-m','remote card'],cwd=git,env=a.env)
            run(['git','verify-commit','HEAD'],cwd=git,env=a.env)
            print('PASS: real GnuPG silent discovery, RSA signing/decryption and Git signing; A has no card with both services enabled, B holds card, C enters PIN',flush=True)

            # Native scdaemon's wrapped PIN cache belongs to its persistent process.
            # Real gpg-agent must return the opaque value, without another pinentry.
            b.card(dict(card, pin_cache=True))
            attempts = c.root/'pinentry-attempts'
            attempts.write_text('0')
            c.mode(sequence=['123456'])
            before = set(b.root.glob('scdaemon-*'))
            a.gpg('--batch','--local-user',fpr,'--detach-sign',data=b'cache first')
            after_first = int(attempts.read_text())
            assert after_first == 1, after_first
            a.gpg('--batch','--local-user',fpr,'--detach-sign',data=b'cache second')
            assert int(attempts.read_text()) == after_first, 'continuous signing asked for PIN again'
            assert set(b.root.glob('scdaemon-*')) == before, 'continuous signing restarted scdaemon'
            assert 'hit' in (b.root/'card-cache-events').read_text()
            # Public rediscovery must preserve cache; explicit RESET invalidates it.
            a.gpg('--card-status')
            assert int(attempts.read_text()) == after_first
            run(['gpg-connect-agent', '--homedir', a.native, 'SCD RESET', '/bye'], env=a.env)
            a.gpg('--batch','--local-user',fpr,'--detach-sign',data=b'cache after reset')
            assert int(attempts.read_text()) == after_first + 1
            b.card(card)
            attempts.write_text('0')
            c.mode(password='123456')
            print('PASS: real gpg-agent PINCACHE round trip avoids a second PIN prompt and reuses native scdaemon',flush=True)
            a.card(dict(card, serial='D2760001240103040005000099990000', keys=[]))
            signed = a.gpg('--local-user', fpr, '--detach-sign', data=b'card message').stdout
            signature.write_bytes(signed); a.gpg('--verify', signature, message)
            assert a.gpg('--decrypt', data=cipher).stdout == b'card secret'
            a.card(dict(card, present=False))
            print('PASS: an unrelated local card does not hide the remote signing/decryption key', flush=True)
            signed = missing_card_prompt(a, b, c, card, ['--local-user', fpr, '--detach-sign'], b'card message')
            signature.write_bytes(signed); a.gpg('--verify', signature, message)
            assert missing_card_prompt(a, b, c, card, ['--decrypt'], cipher) == b'card secret'
            missing_card_prompt(a, b, c, card, ['--local-user', fpr, '--detach-sign'], b'cancel missing card', cancel=True)
            print('PASS: gpg-agent shows the numbered insertion prompt with absent/offline cards; confirmation rechecks all devices, wrong cards fail, Cancel ends the operation', flush=True)
            a.kill_agent(); a.services(); a.restart()


            # A software private key stays in A; native agent retries the bad remote password.
            a.gpg('--batch','--pinentry-mode','loopback','--passphrase','integration-passphrase','--quick-generate-key','Local Test <local@example.test>','rsa2048','sign','0')
            local_listing=a.gpg('--with-colons','--list-secret-keys','local@example.test').stdout.decode()
            local_fpr=next(l.split(':')[9] for l in local_listing.splitlines() if l.startswith('fpr:'))
            c.mode(sequence=['incorrect','integration-passphrase'])
            local_sig=a.gpg('--batch','--local-user',local_fpr,'--detach-sign',data=b'card message').stdout
            signature.write_bytes(local_sig);a.gpg('--verify',signature,message)
            assert int((c.root/'pinentry-attempts').read_text())>=2
            c.mode(password='123456')
            print('PASS: local software key, remote passphrase entry and native wrong-password retry',flush=True)

            # Read-only discovery races, binding and rejected administration.
            a.kill_agent();wait_for(lambda:b.idle('scdaemon'))
            with Assuan(a,'scdaemon') as sc:
                assert sc.command(b'GETINFO socket_name')[-1].startswith(b'ERR 58')
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
                assert sc.command(b'GETATTR SERIALNO')[-1]==b'OK'
                with Assuan(c,'scdaemon') as busy: assert busy.command(b'SERIALNO')[-1].startswith(b'ERR')
                for command in [b'PASSWD',b'GENKEY 1',b'APDU 00A40000',b'WRITEKEY OPENPGP.1']:
                    assert sc.command(command)[-1].startswith(b'ERR 60')
                assert sc.command(b'RESTART')[-1]==b'OK'
                assert sc.command(b'SERIALNO')[-1]==b'OK'
            wait_for(lambda:b.idle('scdaemon'))
            print('PASS: stdio-only capabilities, card binding, backend busy, reset and management restrictions',flush=True)

            # A first failed public query must neither bind nor poison the session.
            with Assuan(a, 'scdaemon') as sc:
                started = time.monotonic()
                assert sc.command(b'READKEY OPENPGP.99') == [b'ERR 17 No key']
                assert time.monotonic() - started < 3, 'definitive error retried until deadline'
                assert sc.command(b'READKEY OPENPGP.1')[-1] == b'OK'
                assert sc.command(b'READKEY OPENPGP.99') == [b'ERR 17 No key']
                assert sc.command(b'GETATTR SERIALNO')[-1] == b'OK'
            wait_for(lambda:b.idle('scdaemon'))
            print('PASS: first and selected missing-key queries preserve native errors without requiring RESET', flush=True)

            # The fastest present card is not necessarily the requested card.
            other={'serial':'D2760001240103040005000099990000','keys':[]}
            # A wrong-card candidate must not prompt during discovery.
            c.mode(delay=10)
            c.card(other);c.services(scdaemon=True,pinentry=True);c.restart()
            card['delay']=.15;b.card(card)
            with Assuan(a,'scdaemon') as sc:
                reply=sc.command(('SERIALNO --demand='+card['serial']).encode())
                assert ('S SERIALNO '+card['serial']).encode() in reply
                assert sc.command(b'RESTART')[-1]==b'OK'
                assert ('S SERIALNO '+other['serial']).encode() in sc.command(b'SERIALNO')
                reply=sc.command(('KEYINFO '+card['keys'][0]['grip']).encode())
                assert any(card['serial'].encode() in l for l in reply),reply
                assert sc.command(b'SETDATA '+b'00'*32)[-1] == b'OK'
                assert sc.command(('PKSIGN --hash=sha256 '+card['keys'][0]['grip']).encode(), lambda _: [b'D 123456',b'END'])[-1] == b'OK'
                b.stop()
                assert sc.command(b'GETATTR SERIALNO')[-1].startswith(b'ERR')
                b.start()
                assert sc.command(b'SETDATA 00')[-1].startswith(b'ERR'), 'failed session silently switched card'
                assert sc.command(b'RESTART')[-1]==b'OK'
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
            wait_for(lambda:b.idle('scdaemon') and c.idle('scdaemon'))
            print('PASS: serial/keygrip matching excludes faster wrong cards; lost bindings require explicit reset',flush=True)

            # An offline member must not delay a native query result or cause
            # retries. A later query can still succeed without RESET.
            a.services(timeout=2); a.restart(); c.stop()
            try:
                with Assuan(a, 'scdaemon') as sc:
                    before = (b.root/'card-commands.log').read_text().count('READKEY OPENPGP.99\n')
                    started = time.monotonic()
                    assert sc.command(b'READKEY OPENPGP.99') == [b'ERR 17 No key']
                    assert time.monotonic() - started < 1.5, 'offline member delayed discovery'
                    assert (b.root/'card-commands.log').read_text().count('READKEY OPENPGP.99\n') == before + 1
                    assert sc.command(b'READKEY OPENPGP.1')[-1] == b'OK'
            finally:
                c.start()
            print('PASS: offline candidates do not delay or mask native discovery results', flush=True)

            # Only local pinentry remains available.
            a.services(pinentry=True);b.services(scdaemon=True);c.services()
            a.mode(password='local only')
            for d in devices:d.restart()
            with Assuan(a,'pinentry') as pe: assert b'D local only' in pe.command(b'GETPIN')
            pinentry_compatibility(a, a)
            print('PASS: local pinentry preserves RESET options and consumes one-shot settings on success/cancel/failure', flush=True)
            a.mode(cancel=True)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'GETPIN')==[b'ERR 83886179 canceled'], 'disabled peers changed cancellation into a failure'
            a.mode(partial_error=True)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'GETPIN')==[b'ERR 1 failed'], 'failed candidate leaked partial data or changed the native error'
            a.services(timeout=1);a.restart();c.services(pinentry=True);c.mode(delay=4);c.restart()
            with Assuan(a,'scdaemon') as sc:
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
                time.sleep(1.2)
                assert sc.command(b'GETATTR SERIALNO')[-1]==b'OK', 'idle session consumed the next command deadline'
            with Assuan(a,'pinentry') as pe:
                for line in [b'SETERROR Retry', b'SETREPEAT Again', b'SETQUALITYBAR Quality']:
                    assert pe.command(line) == [b'OK']
                assert pe.command(b'GETPIN')[-1].startswith(b'ERR')
                wait_for(c.idle)
                c.mode(delay=.01)
                record = c.root/'pinentry-record-commands'; record.touch()
                try:
                    before = set(c.root.glob('pinentry-replay-*.json'))
                    assert pe.command(b'GETPIN')[-1] == b'OK'
                    paths = wait_for(lambda: set(c.root.glob('pinentry-replay-*.json')) - before)
                    assert len(paths) == 1
                    replay = json.loads(paths.pop().read_text())
                    assert not {'SETERROR', 'SETREPEAT', 'SETQUALITYBAR'}.intersection(replay), replay
                finally:
                    record.unlink()
            wait_for(lambda:c.idle())
            print('PASS: all service switch combinations, local-only input and active-command timeout',flush=True)

            a.services();a.restart();c.mode(delay=4)
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(c.waiting);pe.close();wait_for(c.idle)
            print('PASS: caller EOF cancels the remote native pinentry',flush=True)

            # Relay loss ends the active operation; reconnect cannot replay it.
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(c.waiting)
            server.terminate();server.wait(timeout=10)
            assert pe.result()[-1].startswith(b'ERR');pe.close();wait_for(c.idle)
            counts=[len(list(d.root.glob('pinentry-[0-9]*'))) for d in devices]
            config.write_text(config.read_text().replace('127.0.0.1:0','127.0.0.1:'+port))
            server=subprocess.Popen([str(SERVER),'--config',str(config)],stdout=log,stderr=log)
            wait_for(lambda:all(d.log_path.read_text().count('Hibiki daemon connected')>=2 for d in devices),timeout=45)
            assert counts==[len(list(d.root.glob('pinentry-[0-9]*'))) for d in devices]
            c.mode(delay=.05)
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN')[-1]==b'OK'
            print('PASS: WebSocket loss cancels input; reconnect accepts new work without replay',flush=True)

            c.mode(delay=4)
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(c.waiting)
            a.cli('channel','revoke','test',c.id)
            assert pe.result()[-1].startswith(b'ERR');pe.close();wait_for(c.idle)
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN')[-1].startswith(b'ERR')
            b.services(scdaemon=True,pinentry=True);b.mode(delay=4);b.restart()
            print('PASS: membership revocation closes an active prompt and prevents future requests',flush=True)

            # Channel deletion invalidates active and future service sessions.
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(b.waiting)
            run([SERVER,'--config',config,'channel','delete','test'])
            pe.p.wait(timeout=12);pe.close();wait_for(b.idle)
            print('PASS: online channel deletion closes active service sessions',flush=True)

            server.terminate(); server.wait(timeout=10)
            a.stop(); a.services(timeout=1)
            a.log = a.log_path.open('w')
            a.daemon = subprocess.Popen([str(CLIENT), 'daemon'], env=a.env, stdout=a.log, stderr=a.log)
            wait_for(lambda: 'relay unavailable' in a.log_path.read_text())
            status = a.cli('status', ok=False)
            assert b'daemon: running; relay: reconnecting' in status.stdout
            adapter = subprocess.Popen([str(BIN/'hibiki-pinentry')], env=a.env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(adapter.stdout, selectors.EVENT_READ)
                    assert selector.select(4), 'local adapter greeting waited for relay'
                response = adapter.stdout.readline()
                assert response.startswith(b'OK '), response
                adapter.stdin.write(b'GETPIN\n');adapter.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(adapter.stdout, selectors.EVENT_READ)
                    assert selector.select(4), 'remote-only command exceeded its deadline'
                assert adapter.stdout.readline().startswith(b'ERR ')
            finally:
                adapter.terminate(); adapter.wait(timeout=5)
                adapter.stdin.close(); adapter.stdout.close(); adapter.stderr.close()
            a.stop(); a.services(scdaemon=True)
            a.config.write_text(a.config.read_text().replace(str(a.root/'test-scdaemon'), str(a.root/'missing-scdaemon')))
            error = a.cli('daemon', ok=False).stderr
            assert b'enabled but unavailable' in error, error
            print('PASS: live offline status, immediate adapter greeting, bounded remote command and enabled-provider preflight', flush=True)

        except Exception:
            for d in devices:
                print('DIAGNOSTIC',d.root.name, d.log_path.read_text() if hasattr(d,'log_path') else '',file=sys.stderr)
                if (d.root/'pinentry-description.txt').exists(): print((d.root/'pinentry-description.txt').read_text(),file=sys.stderr)
                if (d.root/'card-commands.log').exists(): print((d.root/'card-commands.log').read_text(),file=sys.stderr)
            raise
        finally:
            for d in devices:
                d.kill_agent();d.stop()
            if server.poll() is None:server.terminate();server.wait(timeout=10)
            log.close()

if __name__=='__main__':test_all()
