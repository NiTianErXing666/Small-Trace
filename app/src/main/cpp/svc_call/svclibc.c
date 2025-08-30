//
// Created by Administrator on 2025/8/29.
//

#include "svclibc.h"
// svclibc.c — Minimal libc-like wrappers using svccall()


// 可选：设置 errno 的弱符号（只有当你打开 SVCLIBC_SET_ERRNO=1 才会触发）
#if SVCLIBC_SET_ERRNO
extern void __set_errno_internal(int) __attribute__((weak));
#endif

// 内部：将 raw rv 规范化
static inline long __sv_fix(long rv) {
#if SVCLIBC_SET_ERRNO
    if ((unsigned long)rv >= (unsigned long)-4095) {
        if (__set_errno_internal) __set_errno_internal((int)-rv);
        return -1;
    }
#endif
    return rv;
}

// ---- 文件与 I/O ----
int sv_open(const char* path, int flags, sv_mode_t mode) {
    long rv = svccall(__NR_openat, (long)AT_FDCWD, (long)path, (long)flags, (long)mode, 0L, 0L);
    return (int)__sv_fix(rv);
}

int sv_openat(int dirfd, const char* path, int flags, sv_mode_t mode) {
    long rv = svccall(__NR_openat, (long)dirfd, (long)path, (long)flags, (long)mode, 0L, 0L);
    return (int)__sv_fix(rv);
}

sv_ssize_t sv_read(int fd, void* buf, sv_size_t n) {
    long rv = svccall(__NR_read, (long)fd, (long)buf, (long)n, 0L, 0L, 0L);
    return (sv_ssize_t)__sv_fix(rv);
}

sv_ssize_t sv_write(int fd, const void* buf, sv_size_t n) {
    long rv = svccall(__NR_write, (long)fd, (long)buf, (long)n, 0L, 0L, 0L);
    return (sv_ssize_t)__sv_fix(rv);
}

int sv_close(int fd) {
    long rv = svccall(__NR_close, (long)fd, 0L, 0L, 0L, 0L, 0L);
    return (int)__sv_fix(rv);
}

sv_off_t sv_lseek(int fd, sv_off_t off, int whence) {
    long rv = svccall(__NR_lseek, (long)fd, (long)off, (long)whence, 0L, 0L, 0L);
    return (sv_off_t)__sv_fix(rv);
}

// ---- 内存管理 ----
void* sv_mmap(void* addr, sv_size_t length, int prot, int flags, int fd, sv_off_t offset) {
    long rv = svccall(__NR_mmap, (long)addr, (long)length, (long)prot, (long)flags, (long)fd, (long)offset);
#if SVCLIBC_SET_ERRNO
    if ((unsigned long)rv >= (unsigned long)-4095) {
        if (__set_errno_internal) __set_errno_internal((int)-rv);
        return MAP_FAILED;
    }
#endif
    return (void*)rv; // raw: <0 == -errno；由调用方判断
}

int sv_munmap(void* addr, sv_size_t length) {
    long rv = svccall(__NR_munmap, (long)addr, (long)length, 0L, 0L, 0L, 0L);
    return (int)__sv_fix(rv);
}

int sv_mprotect(void* addr, sv_size_t length, int prot) {
    long rv = svccall(__NR_mprotect, (long)addr, (long)length, (long)prot, 0L, 0L, 0L);
    return (int)__sv_fix(rv);
}

// ---- 时间与进程 ----
int sv_clock_gettime(sv_clockid_t clk, sv_timespec* ts) {
    long rv = svccall(__NR_clock_gettime, (long)clk, (long)ts, 0L, 0L, 0L, 0L);
    return (int)__sv_fix(rv);
}

int sv_nanosleep(const sv_timespec* req, sv_timespec* rem) {
    long rv = svccall(__NR_nanosleep, (long)req, (long)rem, 0L, 0L, 0L, 0L);
    return (int)__sv_fix(rv);
}

sv_pid_t sv_getpid(void) {
    long rv = svccall(__NR_getpid, 0L,0L,0L,0L,0L,0L);
    // getpid 不会负值错误；但保持一致性
    return (sv_pid_t)__sv_fix(rv);
}

int sv_gettid(void) {
    long rv = svccall(__NR_gettid, 0L,0L,0L,0L,0L,0L);
    return (int)__sv_fix(rv);
}
