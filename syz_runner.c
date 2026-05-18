#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <linux/io_uring.h>
#include <linux/if_alg.h>

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#define NUM_THREADS 4
#define ITERATIONS 10000000
volatile int stop = 0;

/* Global randomness */
static int get_rand(void) { return rand(); }

static void xwrite(const char *s)
{
    write(2, s, strlen(s));
}

/* Create a user namespace with root mapping */
static void enter_userns(void)
{
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return;
    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }
}

/* Thread 1: io_uring fuzzer */
static void *fuzz_uring(void *arg)
{
    while (!stop) {
        int mode = rand() % 6;
        struct io_uring_params p = {};
        if (mode == 0) p.flags = IORING_SETUP_SQPOLL;
        if (mode == 1) p.flags = IORING_SETUP_IOPOLL;
        if (mode == 2) p.flags = IORING_SETUP_SQ_AFF;
        
        int ring = syscall(__NR_io_uring_setup, (rand() % 128) + 1, &p);
        if (ring < 0) continue;

        /* Random mmap of sq/cq */
        void *sq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
        void *cq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
        void *se = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);

        if (sq != MAP_FAILED && cq != MAP_FAILED && se != MAP_FAILED) {
            /* Submit random opcodes */
            uint32_t *tail = (uint32_t *)((char *)sq + p.sq_off.tail);
            uint32_t *arr = (uint32_t *)((char *)sq + p.sq_off.array);
            uint32_t idx = *tail;
            struct io_uring_sqe *sqe = &((struct io_uring_sqe *)se)[idx & (p.sq_entries - 1)];
            memset(sqe, 0, sizeof(*sqe));
            sqe->opcode = rand() % 45;
            sqe->fd = rand() % 5 - 2;
            sqe->off = (unsigned long)mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            sqe->addr = rand() | ((unsigned long)rand() << 32);
            sqe->len = rand() % 16384;
            sqe->user_data = idx;
            arr[idx & (p.sq_entries - 1)] = idx & (p.sq_entries - 1);
            __sync_synchronize();
            *tail = idx + 1;
            syscall(__NR_io_uring_enter, ring, 1, rand() % 2, rand() % 2, NULL, 0);

            /* Register random buffers/files */
            syscall(__NR_io_uring_register, ring, 0, NULL, 0);
            syscall(__NR_io_uring_register, ring, 1, NULL, 0);
        }
        if (sq != MAP_FAILED) munmap(sq, 4096);
        if (cq != MAP_FAILED) munmap(cq, 4096);
        if (se != MAP_FAILED) munmap(se, 4096);
        close(ring);
    }
    return NULL;
}

/* Thread 2: userfaultfd + memory operations */
static void *fuzz_uffd_mem(void *arg)
{
    while (!stop) {
        long uffd = syscall(__NR_userfaultfd, rand() % 3);
        if (uffd < 0) continue;

        void *region = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED) { close(uffd); continue; }

        struct uffdio_api api = {.api = UFFD_API, .features = 0};
        ioctl(uffd, UFFDIO_API, &api);

        if (rand() % 2) {
            struct uffdio_register reg = {
                .range = {.start = (unsigned long)region, .len = 0x10000},
                .mode = UFFDIO_REGISTER_MODE_MISSING
            };
            ioctl(uffd, UFFDIO_REGISTER, &reg);

            /* Touch pages and do madvise */
            volatile char *p = (volatile char *)region;
            for (int i = 0; i < 0x10000; i += 4096) p[i] = rand();
            madvise(region, 0x10000, MADV_DONTNEED);
        }

        munmap(region, 0x100000);
        close(uffd);
    }
    return NULL;
}

/* Thread 3: filesystem + mount operations */
static void *fuzz_mount(void *arg)
{
    while (!stop) {
        int m = rand() % 4;
        switch (m) {
        case 0: {
            int mfd = syscall(__NR_memfd_create, "x", 0);
            if (mfd >= 0) { close(mfd); }
            break;
        }
        case 1: {
            int fd = syscall(__NR_fsopen, "tmpfs", 0);
            if (fd >= 0) {
                syscall(__NR_fsconfig, fd, rand()%6, "size", "0", 0);
                syscall(__NR_fsconfig, fd, 5, NULL, NULL, 0);
                int mnt = syscall(__NR_fsmount, fd, 0, 0);
                if (mnt >= 0) {
                    char path[64];
                    snprintf(path, sizeof(path), "/tmp/xx%d", rand());
                    mkdir(path, 0755);
                    syscall(__NR_move_mount, mnt, "", -1, path, 0);
                    close(mnt);
                }
                close(fd);
            }
            break;
        }
        case 2: {
            int fds[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
            if (rand() % 2) splice(fds[0], NULL, fds[1], NULL, 4096, 0);
            if (rand() % 2) tee(fds[0], fds[1], 4096, 0);
            close(fds[0]); close(fds[1]);
            break;
        }
        case 3: {
            int fd = open("/proc/self/mem", O_RDWR);
            if (fd >= 0) {
                unsigned long addr = (unsigned long)mmap(0, 4096, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
                if (addr != MAP_FAILED) {
                    pwrite(fd, "AAAA", 4, addr);
                    munmap((void*)addr, 4096);
                }
                pwrite(fd, "AAAA", 4, 0);
                close(fd);
            }
            break;
        }
        }
    }
    return NULL;
}

/* Thread 4: socket + AF_ALG operations */
static void *fuzz_sock(void *arg)
{
    while (!stop) {
        int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (s >= 0) {
            struct sockaddr_alg sa = {
                .salg_family = AF_ALG,
                .salg_type = "hash",
            };
            memcpy(sa.salg_name, "sha256", 7);
            bind(s, (struct sockaddr *)&sa, sizeof(sa));
            int c = accept(s, NULL, 0);
            if (c >= 0) close(c);
            close(s);
        }
    }
    return NULL;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("=== syzkaller-style kernel fuzzer ===\n");
    printf("PID: %d\n", getpid());
    printf("Targeting: io_uring, userfaultfd, filesystem, socket\n\n");

    int parent_uid = getuid();
    /* Fork into user namespace */
    pid_t child = fork();
    if (child == 0) {
        srand(time(NULL) ^ getpid());
        /* Pass parent uid for namespace setup */
        {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) _exit(1);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", parent_uid); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }
        }
        printf("[child] Inside user namespace (uid=%d real=%d)\n", getuid(), geteuid());
        printf("[child] Starting fuzzer threads...\n");

        pthread_t threads[NUM_THREADS];
        pthread_create(&threads[0], NULL, fuzz_uring, NULL);
        pthread_create(&threads[1], NULL, fuzz_uffd_mem, NULL);
        pthread_create(&threads[2], NULL, fuzz_mount, NULL);
        pthread_create(&threads[3], NULL, fuzz_sock, NULL);

        printf("[child] Running... (^C to stop)\n");
        sleep(60);
        stop = 1;

        for (int i = 0; i < NUM_THREADS; i++)
            pthread_join(threads[i], NULL);
        printf("[child] Done\n");
        _exit(0);
    } else if (child > 0) {
        int status;
        signal(SIGALRM, SIG_IGN);
        alarm(120);
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("\n!!! CRASHED with signal %d !!!\n", WTERMSIG(status));
            return 1;
        }
        printf("[parent] Child exited OK\n");
    }
    return 0;
}
