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
    /* crash with SIGSEGV — triggers kernel core_pattern -> apport */
    raise(SIGSEGV);
    return 0;
}
