# Breach-Entry — build del PoC y herramientas de auditoría
# Uso: make all   (compila los binarios C; los scripts Python no requieren build)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
PTHREAD  = -pthread

BINS = pwn_apport exploit_harness stress_race uffd_race_poc syz_runner

all: $(BINS)

pwn_apport: pwn_apport.c
	$(CC) $(CFLAGS) -o $@ $<

exploit_harness: exploit_harness.c
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $<

stress_race: stress_race.c
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $<

uffd_race_poc: uffd_race_poc.c
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $<

syz_runner: syz_runner.c
	$(CC) $(CFLAGS) $(PTHREAD) -o $@ $<

clean:
	rm -f $(BINS)

.PHONY: all clean
