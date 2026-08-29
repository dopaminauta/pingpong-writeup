# PingPong Writeup

Writeup completo del lab **PingPong** (HTB, dual-forest Active Directory, Kerberos-only).

## Contenido

- [WRITEUP_PINGPONG.md](WRITEUP_PINGPONG.md): el writeup completo (resumen ejecutivo, arquitectura, timeline, fases con comandos, detección blue team, lecciones y honestidad).

## Flags

- User (PONG/DC2): `[REDACTED]`
- Root (PING/DC1): `[REDACTED]`

## Cadena resumida

```
ESC13 (TemporaryWinRM) → WinRM DC1
RBCD gMSA + SPN NetBIOS del SQL → sysadmin → EfsPotato → SYSTEM DC2 → NTDS → DA PONG
R.Martinelli (CA Manager cross-forest) → ESC4 (SmartcardAuthentication) → ESC1 → PKINIT → DA PING
```

## Notas

- Credenciales en claro redactadas por OPSEC (se indican con `<REDACTED>`).
- Detalle de honestidad (qué fue propio y qué vino de una pista externa) en la sección correspondiente del writeup.
