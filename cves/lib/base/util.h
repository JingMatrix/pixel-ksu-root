#pragma once
/*
 * cves/lib/base/util.h - header-only, dependency-free process/syscall utilities.
 *
 * Public surface: SYSCHK / SYSCHK_pr, ASSERT / ASSERT_pr,
 * pr_error / pr_warning / pr_info / pr_success, wait_input, pin_to_core,
 * reset_cpu_pin, set_limit, set_unbuffer, set_proc_name, gettime_ns,
 * write_file, set_user_namespace, hexdump, parse_ul, parse_xl, MAX/MIN.
 *
 * No device/kernel-version constants live here. Every macro is #ifndef-guarded
 * so this header coexists with an exploit's own local #defines. Depends only on
 * libc + Android NDK headers (and, under ANDROID_APP_NO_LKM, android/log.h).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/mman.h>
#include <sched.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>

#ifdef ANDROID_APP_NO_LKM
#include <android/log.h>
#endif

#ifndef HIDEMINMAX
#ifndef MAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#endif
#ifndef MIN
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif
#endif

// #define DEBUG
// #define PANIC

#ifndef COLOR_GREEN
#define COLOR_GREEN "\033[32m"
#endif
#ifndef COLOR_RED
#define COLOR_RED "\033[31m"
#endif
#ifndef COLOR_YELLOW
#define COLOR_YELLOW "\033[33m"
#endif
#ifndef COLOR_DEFAULT
#define COLOR_DEFAULT "\033[0m"
#endif

#ifndef SYSCHK
#define SYSCHK(x) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error("SYSCHK(" #x "): %m\n"); \
        __res; \
    })
#endif
#ifndef SYSCHK_pr
#define SYSCHK_pr(x, fmt) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error(fmt); \
        __res; \
    })
#endif

#ifndef PR_ASSERT
#ifdef PANIC
#define PR_ASSERT pr_error
#else
#define PR_ASSERT pr_warning
#endif
#endif

#ifndef ASSERT
#define ASSERT(cond) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(" #cond ")\n"); \
    } while (0)
#endif
#ifndef ASSERT_pr
#define ASSERT_pr(cond, fmt, ...) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(%s): " fmt, #cond, ##__VA_ARGS__); \
    } while (0)
#endif

#ifndef pr_error
#ifdef DEBUG
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_error(fmt, ...) do { \
        printf(COLOR_RED "[!] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf(COLOR_RED "[-] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf(COLOR_YELLOW "[*] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf(COLOR_GREEN "[+] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#endif
#else
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] " fmt, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] " fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_error(fmt, ...) do { \
        printf(COLOR_RED "[!] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf(COLOR_RED "[-] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf(COLOR_YELLOW "[*] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf(COLOR_GREEN "[+] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#endif
#endif
#endif /* pr_error */

#ifndef wait_input
#define wait_input(fmt, ...) do { \
        pr_info(fmt, ##__VA_ARGS__); getchar(); \
    } while (0)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline void pin_to_core(size_t core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void reset_cpu_pin(void)
{
    cpu_set_t cpuset;
    memset(&cpuset, 0xff, sizeof(cpu_set_t));
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void set_limit(void)
{
    struct rlimit r;
    SYSCHK(getrlimit(RLIMIT_NOFILE, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NOFILE, &r));
    SYSCHK(getrlimit(RLIMIT_NPROC, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NPROC, &r));
}

static inline void set_unbuffer(void)
{
    SYSCHK(setvbuf(stdin,  NULL, _IONBF, 0));
    SYSCHK(setvbuf(stdout, NULL, _IONBF, 0));
    SYSCHK(setvbuf(stderr, NULL, _IONBF, 0));
}

static inline void set_proc_name(const char *name)
{
    SYSCHK(prctl(PR_SET_NAME, name, 0, 0, 0));
}

static inline size_t gettime_ns(void)
{
    struct timespec t;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_nsec + t.tv_sec*1000000000ULL;
}

static void write_file(const char *path, const char *data)
{
    int fd = SYSCHK(open(path, O_WRONLY));
    if (write(fd, data, strlen(data)) != (ssize_t)strlen(data))
        pr_error("write(%s): %m\n", path);
    close(fd);
}


static inline void set_user_namespace(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    SYSCHK(unshare(CLONE_NEWUSER | CLONE_NEWNET));

    write_file("/proc/self/setgroups", "deny");

    char map[128];
    snprintf(map, sizeof(map), "0 %d 1\n", uid);
    write_file("/proc/self/uid_map", map);

    snprintf(map, sizeof(map), "0 %d 1\n", gid);
    write_file("/proc/self/gid_map", map);
}

static inline void hexdump(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static inline unsigned long parse_ul(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}

static inline unsigned long parse_xl(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 16);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}
