#pragma once
// svccall.h — AArch64 secure system call (JIT-decrypt + SVC), no libc required.

#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// 配置项（可在包含前自行 #define 覆盖）
#ifndef SVCCALL_SET_ERRNO
#define SVCCALL_SET_ERRNO 0     // 1: 失败时返回 -1 并设置 errno；0: 返回 raw -errno
#endif

#ifndef SVCCALL_PAGE_SIZE
#define SVCCALL_PAGE_SIZE 4096  // 通常 4K
#endif

#ifndef SVCCALL_XOR_KEY
#define SVCCALL_XOR_KEY 0xA5u   // thunk 编码 XOR key
#endif

// 导出：与 libc 的 syscall 区分，函数签名保持一致（最多 6 个参数）
long svccall(long nr, ...);

// （可选）常用封装，定义后启用：#define SVCCALL_WITH_WRAPPERS 1
//#define SVCCALL_WITH_WRAPPERS 1
#if defined(SVCCALL_WITH_WRAPPERS) && (SVCCALL_WITH_WRAPPERS)
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_read
#define __NR_read   63
#endif
#ifndef __NR_write
#define __NR_write  64
#endif
#ifndef __NR_close
#define __NR_close  57
#endif
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

static inline long sv_openat(int dirfd, const char* path, int flags, long mode) {
  return svccall(__NR_openat, (long)dirfd, (long)path, (long)flags, (long)mode, 0L, 0L);
}
static inline long sv_read(int fd, void* buf, unsigned long n) {
  return svccall(__NR_read, (long)fd, (long)buf, (long)n, 0L, 0L, 0L);
}
static inline long sv_write(int fd, const void* buf, unsigned long n) {
  return svccall(__NR_write, (long)fd, (long)buf, (long)n, 0L, 0L, 0L);
}
static inline long sv_close(int fd) {
  return svccall(__NR_close, (long)fd, 0L, 0L, 0L, 0L, 0L);
}
#endif

#ifdef __cplusplus
}
#endif
