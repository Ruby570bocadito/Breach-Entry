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
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <linux/io_uring.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/if_alg.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <arpa/inet.h>

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

#define NUM_THREADS 8
#define ITERATIONS 50000
#define NS_ITERATIONS 1000

static volatile int stop_flag = 0;
static volatile int crash_count = 0;
static pthread_mutex_t crash_lock = PTHREAD_MUTEX_INITIALIZER;

/* Report crash */
static void check_crash(int pid)
{
    int status;
    if (waitpid(pid, &status, WNOHANG) > 0) {
        if (WIFSIGNALED(status)) {
            pthread_mutex_lock(&crash_lock);
            crash_count++;
            pthread_mutex_unlock(&crash_lock);
        }
    }
}

/* ============== RACE THREADS ============== */

/* Thread 1: io_uring create/destroy race */
static void *thread_uring(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                struct io_uring_params p = {};
                int ring = syscall(__NR_io_uring_setup, 8, &p);
                if (ring < 0) continue;

                void *sq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
                void *cq = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
                void *se = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);

                if (sq != MAP_FAILED && cq != MAP_FAILED && se != MAP_FAILED) {
                    uint32_t *tail = (uint32_t *)((char *)sq + p.sq_off.tail);
                    uint32_t *arr = (uint32_t *)((char *)sq + p.sq_off.array);
                    uint32_t idx = *tail;
                    struct io_uring_sqe *sqe = &((struct io_uring_sqe *)se)[idx & 7];
                    memset(sqe, 0, sizeof(*sqe));
                    sqe->opcode = 0; /* NOP */
                    arr[idx & 7] = idx & 7;
                    __sync_synchronize();
                    *tail = idx + 1;
                    syscall(__NR_io_uring_enter, ring, 1, 1, 0, NULL, 0);
                }

                if (sq != MAP_FAILED) munmap(sq, 4096);
                if (cq != MAP_FAILED) munmap(cq, 4096);
                if (se != MAP_FAILED) munmap(se, 4096);
                close(ring);
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(100);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

/* Thread 2: userfaultfd race */
static void *thread_uffd(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                long uffd = syscall(__NR_userfaultfd, 0);
                if (uffd < 0) continue;

                void *r = mmap(NULL, 0x20000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (r == MAP_FAILED) { close(uffd); continue; }

                struct uffdio_api a = {.api = UFFD_API, .features = 0};
                ioctl(uffd, UFFDIO_API, &a);

                struct uffdio_register reg = {
                    .range = {.start = (unsigned long)r, .len = 0x1000},
                    .mode = UFFDIO_REGISTER_MODE_MISSING
                };
                ioctl(uffd, UFFDIO_REGISTER, &reg);

                /* Trigger page fault and simultaneously create io_uring */
                volatile char *p = (volatile char *)r;
                (void)*p;

                /* Try to read uffd event */
                struct uffd_msg msg;
                int ret = read(uffd, &msg, sizeof(msg));

                if (ret > 0) {
                    /* Fill page */
                    struct uffdio_copy cp = {
                        .dst = msg.arg.pagefault.address & ~0xfff,
                        .src = (unsigned long)r + 0x10000,
                        .len = 0x1000,
                    };
                    ioctl(uffd, UFFDIO_COPY, &cp);
                }

                munmap(r, 0x20000);
                close(uffd);
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(100);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

/* Thread 3: FUSE + memfd_create race */
static void *thread_fuse_memfd(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                int f = open("/dev/fuse", O_RDWR);
                if (f >= 0) {
                    uint32_t c;
                    ioctl(f, _IOR(229, 0, uint32_t), &c);
                    close(f);
                }
                int mfd = syscall(__NR_memfd_create, "t", 0);
                if (mfd >= 0) {
                    write(mfd, "AAAAAAAA", 8);
                    fcntl(mfd, F_ADD_SEALS, F_SEAL_WRITE|F_SEAL_SHRINK);
                    close(mfd);
                }
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(50);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

/* Thread 4: nf_tables + AF_ALG */
static void *thread_nft_alg(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                /* AF_ALG */
                int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
                if (s >= 0) close(s);

                /* Netlink */
                int sock = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_NETFILTER);
                if (sock >= 0) {
                    char buf[512] = {};
                    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                    struct nfgenmsg *nfg = (struct nfgenmsg *)(buf + sizeof(*nlh));
                    nlh->nlmsg_len = sizeof(*nlh) + sizeof(*nfg);
                    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
                    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
                    nfg->nfgen_family = AF_INET;
                    nfg->version = NFNETLINK_V0;
                    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
                    sendto(sock, buf, nlh->nlmsg_len, 0, (void *)&sa, sizeof(sa));
                    close(sock);
                }
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(50);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

/* Thread 5: Mount/namespace stress */
static void *thread_mount(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                /* Try mount API */
                int mfd = syscall(__NR_fsopen, "tmpfs", 0);
                if (mfd >= 0) {
                    syscall(__NR_fsconfig, mfd, 0, "size", "0", 0);
                    syscall(__NR_fsconfig, mfd, 5, NULL, NULL, 0);
                    int mnt = syscall(__NR_fsmount, mfd, 0, 0);
                    if (mnt >= 0) close(mnt);
                    close(mfd);
                }

                /* Try pivot_root from userns */
                syscall(__NR_pivot_root, ".", ".");

                /* Try chroot */
                chroot("/tmp");
                chdir("/");
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(50);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

/* Thread 6: seccomp + prctl + /proc/self/mem */
static void *thread_seccomp_proc(void *arg)
{
    for (int i = 0; i < NS_ITERATIONS && !stop_flag; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (unshare(CLONE_NEWUSER) != 0) _exit(0);
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getuid()); close(fd); }
            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { write(fd, "deny", 4); close(fd); }
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { dprintf(fd, "0 %d 1", getgid()); close(fd); }

            for (int j = 0; j < ITERATIONS / NS_ITERATIONS; j++) {
                /* prctl operations */
                uint64_t v;
                syscall(__NR_prctl, 0x5961, &v, 0, 0, 0);
                syscall(__NR_prctl, 62, 0, 0, 0, 0);
                syscall(__NR_prctl, 31, 2, 0, 0, 0);  /* PR_SET_SECCOMP SECCOMP_MODE_FILTER */

                /* /proc/self/mem */
                int mfd = open("/proc/self/mem", O_RDWR);
                if (mfd >= 0) {
                    pwrite(mfd, "A", 1, 0);
                    unsigned long s;
                    pwrite(mfd, "A", 1, (unsigned long)&s);
                    close(mfd);
                }

                /* eventfd + signalfd + timerfd */
                int efd = eventfd(0, 0);
                if (efd >= 0) { eventfd_write(efd, 1); close(efd); }
            }
            _exit(0);
        }
        if (pid > 0) {
            usleep(50);
            check_crash(pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
    return NULL;
}

int main(void)
{
    printf("=== Aggressive Race/Stress Test ===\n");
    printf("Threads: %d, Iterations per thread: ~%d\n", NUM_THREADS, NS_ITERATIONS * (ITERATIONS / NS_ITERATIONS));
    printf("PID: %d\n", getpid());
    printf("Starting...\n\n");

    pthread_t threads[NUM_THREADS];

    pthread_create(&threads[0], NULL, thread_uring, NULL);
    pthread_create(&threads[1], NULL, thread_uffd, NULL);
    pthread_create(&threads[2], NULL, thread_fuse_memfd, NULL);
    pthread_create(&threads[3], NULL, thread_nft_alg, NULL);
    pthread_create(&threads[4], NULL, thread_mount, NULL);
    pthread_create(&threads[5], NULL, thread_seccomp_proc, NULL);
    /* Extra load */
    pthread_create(&threads[6], NULL, thread_uring, NULL);
    pthread_create(&threads[7], NULL, thread_uffd, NULL);

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n=== Done ===\n");
    printf("Crashes detected: %d\n", crash_count);

    if (crash_count > 0) {
        printf("SUSPICIOUS: %d crashes detected during stress test!\n", crash_count);
        return 1;
    }
    return 0;
}
