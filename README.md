# PingPong Writeup

Full writeup of the **PingPong** lab (HTB, dual-forest Active Directory, Kerberos-only).

## Contents

- [WRITEUP_PINGPONG.md](WRITEUP_PINGPONG.md): the complete writeup (executive summary, architecture, timeline, phases with commands, blue team detection, lessons and honesty).

## Chain summary

```
ESC13 (TemporaryWinRM) → WinRM on DC1
gMSA RBCD + SQL NetBIOS SPN → sysadmin → EfsPotato → SYSTEM on DC2 → NTDS → DA PONG
R.Martinelli (FSP in PING's "CA Managers") → ESC4 (SmartcardAuthentication) → ESC1 → PKINIT → DA PING
```

## Notes

- Clear-text credentials redacted for OPSEC (shown as `<REDACTED>`).
- The honesty section details what was original and what came from an external hint.
