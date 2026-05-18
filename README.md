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

---

# Comprehensive Audit — Ubuntu Server 24.04.4 LPE Research

## System
- **OS:** Ubuntu Server 24.04.4 LTS
- **Kernel:** 6.8.0-117-generic (build Tue May 5 19:26:24 UTC 2026, custom config)
- **User:** `rafa` (uid 1000), sudo via password
- **SSH:** exposed on 0.0.0.0:22, public IP 99.134.0.2, X11Forwarding yes, no firewall
- **Hardware:** 1 vCPU, 1.3GB RAM, 40GB disk, Hyper-V VM

## Attack Surfaces Investigated

| Surface | Status | Detail |
|---------|--------|--------|
| **Apport bug (CWE-345)** | ✅ Confirmed | Metadata spoofing, NOT LPE — see above |
| **Snap-confine (cap_sys_admin)** | ⚠️ Races found | TOCTOU in `setup_private_tmp` (documented), `/tmp/.snap` mimic (not exploitable without root dirs) — CVE-2026-3888 patched |
| **Polkit/D-Bus** | ⚠️ Partial | udisks2 `filesystem-mount allow_active=yes` (system devices only), no polkit agent → interactive auth fails |
| **LXD socket** | ❌ Not accessible | User not in `lxd` group |
| **algif_aead (Copy Fail)** | ❌ Blacklisted | `/etc/modprobe.d/disable-algif_aead.conf` explicitly blocks it |
| **BPF** | ❌ Locked | `unprivileged_bpf_disabled=2`, not usable from user_ns |
| **nf_tables** | ❌ EPERM from user_ns | Kernel checks init_user_ns |
| **io_uring** | 🔒 No crash found | All 45 opcodes tested, register ops, stress tests — no panics |
| **userfaultfd** | 🔒 No crash found | Works from user_ns with CAP_SYS_PTRACE, no UAF triggered |
| **SSH ssh-keysign (SUID)** | ❌ No vuln found | Standard OpenSSH 9.6p1 |
| **Kernel fuzzing (5 min weighted)** | 🔒 Zero crashes | 4 threads: io_uring + uffd + fs + sockets, all from user_ns |

## Key Kernel Config Differences (vs stock Ubuntu)

| Setting | Custom | Stock | Impact |
|---------|--------|-------|--------|
| `CONFIG_DEBUG_FS_ALLOW_ALL` | `y` | `=NONE` | debugfs mountable by any user (but dir is 0700 root) |
| `CONFIG_SECURITY_APPARMOR_RESTRICT_USERNS` | not set | `y` | User namespaces unrestricted by AppArmor |
| `CONFIG_KASAN` | not set | `y` on debug | No kernel address sanitizer (easier exploitation) |

## Tools Created

| File | Description |
|------|-------------|
| `exploit_harness.c` | 15-test kernel interface battery (all passed) |
| `stress_race.c` | 8-thread race condition stress test (50k iters, 0 crashes) |
| `uffd_race_poc.c` | Userfaultfd + io_uring/memfd/madvise race PoC (0 crashes) |
| `syz_runner.c` | Weighted kernel fuzzer (runs 4 target threads inside user_ns) |
| `syzkaller/` | Built from source at `/tmp/syzkaller/bin/` |

## syzkaller Setup
Built from source and ready for VM fuzzing:
- `/tmp/syzkaller/bin/syz-manager`
- `/tmp/syzkaller/bin/linux_amd64/syz-execprog`
- `/tmp/syzkaller/bin/linux_amd64/syz-executor`
- Kernel source at `/usr/src/linux-source-6.8.0/` (needs KASAN rebuild for effective fuzzing)

## Known Existing CVEs (not new zero-days)
- **Dirty Frag** (disclosed May 7 2026): Kernel build May 5 predates patches
- **CVE-2026-31431 (Copy Fail)**: algif_aead module blacklisted as mitigation
- **CVE-2026-3888 (snap-confine)** : Snapd 2.74.1 patched

## Referencias

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- [CVE-2019-15790](https://nvd.nist.gov/vuln/detail/CVE-2019-15790)
- [CVE-2020-11935](https://nvd.nist.gov/vuln/detail/CVE-2020-11935)
