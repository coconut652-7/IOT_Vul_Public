# H3C NX15 R017 `esps.apcm.version.delete` Authenticated Root Command Injection

## Summary

H3C NX15 Router firmware NX15V100R017 contains an authenticated command injection vulnerability in the `/api/esps` RPC object `esps.apcm.version`, method `delete`. The version string in the `list[]` parameter is filtered incompletely and then passed to `eval`, allowing arbitrary command execution as root.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: `/api/esps` backend RPC
- Vulnerable object: `esps.apcm.version`
- Vulnerable method: `delete`
- Vulnerable parameter: `list[]` version string

## Vulnerability Type

- OS command injection
- Suggested CWE: CWE-78
- Attack vector: Remote
- Authentication required: Yes
- Privileges required: Administrator web session
- User interaction required: No

## Impact

An authenticated attacker can execute arbitrary commands as root. Runtime testing confirmed that a crafted version string can start a root shell and execute commands with UID 0.

## Technical Details

The `delete` branch performs a blacklist check similar to:

```sh
echo "${version}" | grep "[\`\\\"\'\;,]" >/dev/null
```

This filter blocks several characters, including backticks, quotes, semicolons, and commas. However, it does not block shell command substitution characters such as `$`, `(`, and `)`, nor does it block control operators such as `&&`.

The filtered value then reaches:

```sh
eval version"${idx}"="${version}"
```

A payload using `$()` command substitution and `${IFS}` in place of spaces can pass the blacklist and execute during the `eval` assignment.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that accepts authenticated `/api/esps` requests and forwards them to ubus objects.
- `/usr/libexec/rpcd/esps.apcm.version`: vulnerable backend script; the `delete` branch filters the version string incompletely and later reaches `eval`.

## Reproduction

Run the included PoC with valid administrator credentials:

```bash
python3 poc/14_postauth_esps_apcm_version_delete_rce.py \
  --base http://192.168.8.1 \
  --username admin \
  --password '<admin-password>' \
  --port 2323 \
  --cleanup
```

The PoC:

1. Authenticates to the web interface.
2. Calls `/api/esps` with object `esps.apcm.version` and method `delete`.
3. Sends a crafted `list[]` version string.
4. Starts a temporary shell service.
5. Connects to the shell and verifies root execution.

Expected result:

```text
uid=0(root)
```

## Evidence

- Static analysis identified an incomplete blacklist followed by `eval`.
- Runtime verification confirmed command execution through a crafted version string.
- The spawned shell runs with root privileges.

## Attachments

- Report: `report/16_postauth_esps_apcm_version_delete_rce_report.md`
- PoC: `poc/14_postauth_esps_apcm_version_delete_rce.py`

## Remediation

- Remove `eval` from the APCM version backend script.
- Replace blacklist validation with a strict version-format allowlist.
- Reject `$`, parentheses, braces, shell operators, and other metacharacters where they are not valid version characters.
- Restrict `/api/esps` RPC exposure to required safe objects and methods.
