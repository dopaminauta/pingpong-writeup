# 🏓 PingPong: Two Forests, One Bad Day

A Hard dual-forest AD lab from Hack The Box. Kerberos only, so every tool that silently falls back to NTLM will silently fail. The clock is 8 hours in the future, which makes you feel like a time traveler every time you touch Kerberos. RC4 is dead in PONG. And there is a SQL Server that will reject your perfectly valid TGS five times in a row, just because you used the FQDN instead of NetBIOS.

We took both domains anyway.

```
ESC13 (TemporaryWinRM) → WinRM on DC1
gMSA RBCD + SQL NetBIOS SPN → sysadmin → EfsPotato → SYSTEM on DC2 → NTDS → DA PONG
R.Martinelli (FSP in PING's "CA Managers") → ESC4 → ESC1 → PKINIT → DA PING
```

Two forests. Two Domain Admins. One writeup.

The path into PONG is not in any other writeup. We found it ourselves after days of the SQL telling us "untrusted domain" like a broken record. The simplest explanation was the right one, Occam would be proud: the instance validates the NetBIOS SPN of your TGS, not the FQDN. One attribute change and five hours of pain later, we were sysadmin.

The ending is the lab's signature: a PONG account sitting inside PING's custom "CA Managers" group through a Foreign Security Principal. It is a philosophy lesson disguised as a Windows box. Know your FSPs or perish. And when you do the ESC1, remember that KB5014754 wants the user's objectSID (500), not the Domain Admins SID (512). Ask us how we know.

Other highlights for the masochists:

- EfsPotato compiled on the host, because outbound HTTP and SMB are blocked and nobody is mailing you binaries.
- WinRM on Server 2022 uses WSMAN/<fqdn>, not HTTP/<fqdn>. The SPN that does not exist will give you 401s until you question your sanity.
- `certipy find -vulnerable` will not show you the cross-forest ESC4. Look at the DACLs yourself.
- `bloodyAD` does not read /etc/hosts. Welcome to resolv.conf hell.
- evil-winrm 3.9 is broken with ruby 3.4, and the ruby gssapi does not speak AES. Have fun.

Honesty: we got stuck on the last step for hours and ended up reading a public writeup. The answer was in our own NTDS dump the whole time. The "second pass" section proves the ending was findable with systematic enumeration: inventory the cross-forest permissions of every account in your dump. Custom groups with FSPs from other domains are the lab's fingerprint. Getting stuck and learning why is worth more than a clean solve, so we published this anyway.

Full writeup: [WRITEUP_PINGPONG.md](WRITEUP_PINGPONG.md)

---

## Author
**Axel Feduzka** · GitHub [@dopaminauta](https://github.com/dopaminauta) · dominguezfya@gmail.com

---
*Practice walkthrough on a retired HackTheBox machine. All attacks executed in an authorized lab environment; target IPs sanitized.*

---

> *Solve et Coagula: bound by EMET, driven by AHAVA.*
