# H3C NX15 R017 `esps.filter.url.add` Authenticated Root Command Injection

## Summary

H3C NX15 Router firmware NX15V100R017 contains an authenticated command injection vulnerability in the `/api/esps` RPC object `esps.filter.url`, method `add`. The `urls[]` input reaches a shell `eval` assignment without safe quoting or sanitization, allowing an authenticated administrator to execute arbitrary commands as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Vulnerable object: `esps.filter.url`
- Vulnerable method: `add`
- Vulnerable parameter: `urls[]`

## Vulnerability Type

- OS command injection
- Suggested CWE: CWE-78
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can execute arbitrary commands as root. Confirmed impact includes starting a root shell service and executing commands such as `id` and `uname -a` with UID 0.

## Technical Details

The vulnerable backend script reads user-controlled URL entries and stores them in dynamically named shell variables. In the `add` branch, the code path uses `eval` on attacker-controlled data:

```sh
json_get_var urlsStr ${idx}
eval urlsStr"${idx}"="${urlsStr}"
```

Later, the stored values are used while adding URL-filtering rules:

```sh
uci add_list urlfilter.rule"${_id}".urls="$(eval echo '$'"urlsStr${_idx}")"
```

The implementation intends to copy JSON array entries into indexed shell variables. However, if `urlsStr` contains shell command substitution syntax such as `$()`, the command is interpreted during the `eval` assignment.

The vulnerable branch is reachable through:

```text
POST /api/esps
object = esps.filter.url
method = add
```

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `/usr/libexec/rpcd/esps.filter.url`: vulnerable backend script; the `add` branch reads `urls[]` and reaches the unsafe `eval` assignment.
- `/etc/config/urlfilter`: UCI configuration file affected by URL-filter rule writes.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/12_postauth_esps_filter_url_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2323 \
  --cleanup
```

The PoC:

1. Logs in through `/api/login/auth`.
2. Calls `/api/esps` with object `esps.filter.url` and method `add`.
3. Places a command-substitution payload in `urls[]`.
4. Starts a temporary `telnetd` shell.
5. Connects to the shell and verifies root command execution.

Expected result:

```text
uid=0(root)
```

## Evidence

- Static analysis identified attacker-controlled `urls[]` reaching an `eval` assignment.
- The input filter does not prevent shell command substitution.
- Runtime verification confirmed that a payload in `urls[]` starts a root shell and executes commands as root.

## Attachments

- Report: `report/13_postauth_esps_filter_url_rce_report.md`
- PoC: `poc/12_postauth_esps_filter_url_rce.py`

## Remediation

- Remove `eval` from the URL-filtering backend script.
- Store JSON array values using safe shell quoting or a non-shell parser.
- Reject shell metacharacters in URL fields where they are not valid input.
- Restrict `/api/esps` to an allowlist of safe objects and methods.
