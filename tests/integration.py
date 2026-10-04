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
    def kill_agent(self): run([GPGCONF,'--homedir',self.native,'--kill','gpg-agent'],env=self.env)
    def start(self):
        self.log_path=self.root/'daemon.log';self.log=self.log_path.open('w')
        self.daemon=subprocess.Popen([str(CLIENT),'daemon'],env=self.env,stdout=self.log,stderr=self.log)
        def ready():
            assert self.daemon.poll() is None,self.log_path.read_text()
            return 'HIbiki daemon connected' in self.log_path.read_text()
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
    (device.root/'card.json').write_text(json.dumps(card));(device.root/'card.json').chmod(0o600)
    return fpr,device.gpg('--export',fpr).stdout,card

def test_all():
    with tempfile.TemporaryDirectory(prefix='hi-',dir='/tmp') as temp:
        root=Path(temp);server_data=root/'server';server_data.mkdir(mode=0o700)
        config=server_data/'server.toml';config.write_text('listen = "127.0.0.1:0"\ndatabase = "hibiki.sqlite3"\nallow_client_channel_creation = false\n')
        server_log=server_data/'server.log';log=server_log.open('w')
        server=subprocess.Popen([str(SERVER),'--config',str(config)],stdout=log,stderr=log)
        devices=[]
        try:
            def listening():
                assert server.poll() is None,server_log.read_text()
                return re.search(r'listening on 127.0.0.1:(\d+)',server_log.read_text())
            port=wait_for(listening).group(1);url='ws://127.0.0.1:%s/hibiki'%port
            a,b,c=[Device(root,name,url) for name in ('a','b','c')];devices=[a,b,c]
            psk=root/'psk';psk.write_text(secrets.token_urlsafe(32));psk.chmod(0o600)
            a.cli('channel','create','forbidden','--psk-file',psk,ok=False)
            created=run([SERVER,'--config',config,'channel','create','test','--server',url,'--psk-file',psk]).stdout.decode().splitlines()
            bootstrap=created[1].split()[1]
            a.cli('channel','join',bootstrap,'--psk-file',psk)
            b.cli('channel','join',bootstrap,'--psk-file',psk,ok=False)
            invite=a.cli('channel','invite','test').stdout.decode().strip()
            for member,approver in [(b,a),(c,b)]:
                joined=member.cli('channel','join',invite,'--psk-file',psk,'--no-wait')
                request=joined.stdout.decode().split()[1]
                approver.cli('channel','approve','test',request,data=b'\n')
                assert request.encode() in approver.cli('channel','pending','test').stdout
                approver.cli('channel','approve','test',request,data=b'y\n')
                member.cli('channel','list')
            for d in devices: d.cli('channel','list');d.cli('use','test')
            fpr,public,card=make_card(b)
            a.gpg('--import',data=public)
            a.services();b.services(scdaemon=True,pinentry=True);c.services(pinentry=True)
            for d in devices: d.start()
            print('PASS: fresh HIbiki pairing, server-only creation and independent services',flush=True)

            b.mode(delay=.05,cancel=True);c.mode(delay=.2,password='remote answer')
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'SETDESC Test remote input')[-1]==b'OK'
                answer=pe.command(b'GETPIN');assert b'D remote answer' in answer,answer
            wait_for(lambda: all(d.idle() for d in devices))
            print('PASS: requester with both services disabled, single cancellation does not cancel peers',flush=True)

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
            a.services();a.restart();b.mode(cancel=True);c.mode(cancel=True)
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN')==[b'ERR 83886179 canceled']
            print('PASS: local participation, all-cancel and losing process cleanup',flush=True)

            b.mode(cancel=True);c.mode(confirm=True)
            with Assuan(a,'pinentry') as pe:
                assert pe.command(b'SETDESC Confirm remote operation')[-1]==b'OK'
                assert pe.command(b'CONFIRM')==[b'OK']
                assert pe.command(b'MESSAGE')==[b'OK']
            wait_for(lambda: all(d.idle() for d in devices))
            print('PASS: remote confirmation and message dialogs complete without password data',flush=True)

            b.mode(cancel=True);c.mode(password='123456',delay=.1)
            a.configure_agent()
            status=a.gpg('--card-status')
            assert b'00001234' in status.stdout or b'HIbiki test card' in status.stdout,status.stdout
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
            print('PASS: real GnuPG card learning, RSA signing/decryption and native Git signing; A calls, B holds card, C enters PIN',flush=True)

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

            # The fastest present card is not necessarily the requested card.
            other={'serial':'D2760001240103040005000099990000','keys':[]}
            (c.root/'card.json').write_text(json.dumps(other));c.services(scdaemon=True,pinentry=True);c.restart()
            card['delay']=.15;(b.root/'card.json').write_text(json.dumps(card))
            with Assuan(a,'scdaemon') as sc:
                reply=sc.command(('SERIALNO --demand='+card['serial']).encode())
                assert ('S SERIALNO '+card['serial']).encode() in reply
                assert sc.command(b'RESTART')[-1]==b'OK'
                reply=sc.command(('KEYINFO '+card['keys'][0]['grip']).encode())
                assert any(card['serial'].encode() in l for l in reply),reply
                b.stop()
                assert sc.command(b'GETATTR SERIALNO')[-1].startswith(b'ERR')
                b.start()
                assert sc.command(b'SETDATA 00')[-1].startswith(b'ERR'), 'failed session silently switched card'
                assert sc.command(b'RESTART')[-1]==b'OK'
                assert sc.command(('SERIALNO --demand='+card['serial']).encode())[-1]==b'OK'
            wait_for(lambda:b.idle('scdaemon') and c.idle('scdaemon'))
            print('PASS: serial/keygrip matching excludes faster wrong cards; lost bindings require explicit reset',flush=True)

            # Only local pinentry remains available.
            a.services(pinentry=True);b.services(scdaemon=True);c.services()
            a.mode(password='local only')
            for d in devices:d.restart()
            with Assuan(a,'pinentry') as pe: assert b'D local only' in pe.command(b'GETPIN')
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
            with Assuan(a,'pinentry') as pe: assert pe.command(b'GETPIN')[-1].startswith(b'ERR')
            wait_for(lambda:c.idle())
            print('PASS: all service switch combinations, local-only input and active-command timeout',flush=True)

            a.services();a.restart();c.mode(delay=4)
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(c.waiting);pe.close();wait_for(c.idle)
            print('PASS: caller EOF cancels the remote native pinentry',flush=True)

            # Relay loss ends the active operation; reconnect cannot replay it.
            pe=Assuan(a,'pinentry');pe.send(b'GETPIN');wait_for(c.waiting)
            server.terminate();server.wait(timeout=10)
            pe.p.wait(timeout=10);pe.close();wait_for(c.idle)
            counts=[len(list(d.root.glob('pinentry-[0-9]*'))) for d in devices]
            config.write_text(config.read_text().replace('127.0.0.1:0','127.0.0.1:'+port))
            server=subprocess.Popen([str(SERVER),'--config',str(config)],stdout=log,stderr=log)
            wait_for(lambda:all(d.log_path.read_text().count('HIbiki daemon connected')>=2 for d in devices),timeout=45)
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
