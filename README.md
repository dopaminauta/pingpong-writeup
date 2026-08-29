# PingPong Writeup

Full walkthrough of **PingPong**, a Hard dual-forest Active Directory lab from Hack The Box.

**The lab:** two forests joined by a bidirectional trust. PING.HTB (DC1) is the external entry point; PONG.HTB (DC2) is internal only. NTLM is disabled everywhere, so every authentication is pure Kerberos, with a lab clock running about 8 hours ahead of UTC and RC4 disabled in PONG (AES256 mandatory).

**The result:** both domains fully compromised. The path spans ADCS ESC13 (WinRM foothold), a gMSA RBCD plus a SQL NetBIOS SPN quirk to reach the internal DC, EfsPotato for SYSTEM, an NTDS dump for DA PONG, and a cross-forest DACL abuse (a PONG account inside PING's "CA Managers" group via a Foreign Security Principal) chained into ESC4 + ESC1 + PKINIT for DA PING.

## Chain summary

```
ESC13 (TemporaryWinRM) → WinRM on DC1
gMSA RBCD + SQL NetBIOS SPN → sysadmin → EfsPotato → SYSTEM on DC2 → NTDS → DA PONG
R.Martinelli (FSP in PING's "CA Managers") → ESC4 (SmartcardAuthentication) → ESC1 → PKINIT → DA PING
```

## Contents

- [WRITEUP_PINGPONG.md](WRITEUP_PINGPONG.md): the complete writeup (executive summary, architecture, timeline, phases with commands, severity, remediation, blue team detection, lessons and an honesty section).
