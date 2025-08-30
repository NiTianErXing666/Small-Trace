#pragma once
// svclibc.h — Minimal libc-like wrappers built on svccall()
// AArch64/ARM 可用（取决于你提供的 svccall 实现）

#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// === 配置 ===
// 0: 返回 raw -errno（默认，彻底不触 libc）
// 1: 失败时返回 -1 并设置 errno（弱依赖 bionic 的 __set_errno_internal）
#ifndef SVCLIBC_SET_ERRNO
#define SVCLIBC_SET_ERRNO 0
#endif

// 一些常量兜底（避免拉 libc 头）——按需增补
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

#ifndef PROT_READ
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4
#define PROT_NONE   0
#endif

#ifndef MAP_PRIVATE
#define MAP_PRIVATE   2
#define MAP_ANONYMOUS 0x20
#endif

#ifndef O_RDONLY
#define O_RDONLY 0
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif

// AArch64 常用 syscall 号（若你的 <asm/unistd.h> 不可用）
#ifndef __NR_openat
#define __NR_openat       56
#endif
#ifndef __NR_read
#define __NR_read         63
#endif
#ifndef __NR_write
#define __NR_write        64
#endif
#ifndef __NR_close
#define __NR_close        57
#endif
#ifndef __NR_fstat
#define __NR_fstat        80
#endif
#ifndef __NR_lseek
#define __NR_lseek        62
#endif
#ifndef __NR_mmap
#define __NR_mmap         222
#endif
#ifndef __NR_mprotect
#define __NR_mprotect     226
#endif
#ifndef __NR_munmap
#define __NR_munmap       215
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif
#ifndef __NR_nanosleep
#define __NR_nanosleep    101
#endif
#ifndef __NR_getpid
#define __NR_getpid       172
#endif
#ifndef __NR_gettid
#define __NR_gettid       178
#endif

// 轻量类型（避免拉 libc 头）
typedef long            sv_ssize_t;
typedef unsigned long   sv_size_t;
typedef long            sv_off_t;
typedef unsigned int    sv_mode_t;
typedef int             sv_clockid_t;
typedef int             sv_pid_t;
typedef struct { long tv_sec; long tv_nsec; } sv_timespec;

// 你自己的 SVC 系统调用入口（需由你提供实现）
long svccall(long nr, ...);

// ---- libc 风格 API（全部只经由 svccall） ----
// 文件与 I/O
int         sv_open(const char* path, int flags, sv_mode_t mode);
int         sv_openat(int dirfd, const char* path, int flags, sv_mode_t mode);
sv_ssize_t  sv_read(int fd, void* buf, sv_size_t n);
sv_ssize_t  sv_write(int fd, const void* buf, sv_size_t n);
int         sv_close(int fd);
sv_off_t    sv_lseek(int fd, sv_off_t off, int whence);

// 内存管理
void*       sv_mmap(void* addr, sv_size_t length, int prot, int flags, int fd, sv_off_t offset);
int         sv_munmap(void* addr, sv_size_t length);
int         sv_mprotect(void* addr, sv_size_t length, int prot);

// 时间与进程
int         sv_clock_gettime(sv_clockid_t clk, sv_timespec* ts);
int         sv_nanosleep(const sv_timespec* req, sv_timespec* rem);
sv_pid_t    sv_getpid(void);
int         sv_gettid(void);

// 工具：从 raw 返回值取 errno（例如在 SVCLIBC_SET_ERRNO=0 时）
static inline int sv_errcode(long rv) { return (rv < 0) ? (int)(-rv) : 0; }

#ifdef __cplusplus
}
#endif
