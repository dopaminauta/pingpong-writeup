# 🏓 PingPong: Two Forests, One Bad Day

A Hard, dual-forest Active Directory lab from Hack The Box. Kerberos only. NTLM is dead. RC4 is dead in PONG. The clock is 8 hours in the future. And there is a SQL Server that will reject your perfectly valid TGS five times in a row, just because you used the FQDN instead of NetBIOS.

We took both domains anyway.

## The TL;DR

```
ESC13 (TemporaryWinRM) → WinRM on DC1
gMSA RBCD + SQL NetBIOS SPN → sysadmin → EfsPotato → SYSTEM on DC2 → NTDS → DA PONG
R.Martinelli (FSP in PING's "CA Managers") → ESC4 → ESC1 → PKINIT → DA PING
```

Two forests. Two Domain Admins. One writeup.

## Why read this one

- **The path into PONG is not in any other writeup.** We found it ourselves after days: the SQL Express validates the **NetBIOS SPN** of your TGS, not the FQDN. That single detail costs hours and smells like a bug until it is not.
- **EfsPotato, compiled on the host**, because outbound HTTP and SMB are blocked and nobody is mailing you binaries.
- **A cross-forest DACL abuse** that is the lab's signature: a PONG account sitting inside PING's custom "CA Managers" group through a Foreign Security Principal. Learn to spot that group and you will see the ending from a mile away.
- **KB5014754 bites**: the `-sid` in `certipy req` must be the user's objectSID (500), not the Domain Admins SID (512). Ask us how we know.

## The suffering (so you are prepared)

- Clock skew on every single Kerberos call: `faketime "+8 hours"` or perish.
- `certipy find -vulnerable` will not show you the cross-forest ESC4. Look at the DACLs yourself.
- `bloodyAD` does not read `/etc/hosts`. Welcome to resolv.conf hell.
- WinRM on Server 2022 uses `WSMAN/<fqdn>`, not `HTTP/<fqdn>`. The SPN that does not exist will give you 401s forever.
- evil-winrm 3.9 is broken with ruby 3.4. The ruby gssapi does not speak AES. Have fun.

## Honesty corner

We got stuck on the last step for hours and ended up using a public writeup as a hint. The data was in our own NTDS dump the whole time. The "second pass" section proves the ending was findable with systematic enumeration: inventory the cross-forest permissions of every account in your NTDS dump. Custom groups with FSPs from other domains are the lab's fingerprint.

We published this anyway, because getting stuck and learning why is worth more than a clean solve.

## Contents

- [WRITEUP_PINGPONG.md](WRITEUP_PINGPONG.md): full writeup (architecture, timeline, phases with commands, severity, remediation, blue team detection, lessons).

---

*Solved by Camarón 🦐 with the endurance of his father. Written with EMET, Anavah and Tiferet.*
