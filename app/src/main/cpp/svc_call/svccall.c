// svccall.c — AArch64 secure system call (JIT-decrypt + SVC), no libc required.

#include "svccall.h"

#if !defined(__aarch64__)
# error "svccall is implemented for AArch64 only."
#endif

// ---- syscall numbers used internally ----
#ifndef __NR_mmap
# define __NR_mmap       222
#endif
#ifndef __NR_mprotect
# define __NR_mprotect   226
#endif
#ifndef __NR_munmap
# define __NR_munmap     215
#endif

// ---- PROT / MAP flags ----
#ifndef PROT_READ
# define PROT_READ   1
# define PROT_WRITE  2
# define PROT_EXEC   4
# define PROT_NONE   0
#endif
#ifndef MAP_PRIVATE
# define MAP_PRIVATE   2
# define MAP_ANONYMOUS 0x20
#endif

#if SVCCALL_SET_ERRNO
// bionic 内部 errno 设定，弱符号——不存在时不设置 errno，仅返回 -1
extern void __set_errno_internal(int) __attribute__((weak));
#endif

// ---- raw SVC helper（避免任何 libc 依赖） ----
static inline long __svc6(long nr,
                          long a0,long a1,long a2,long a3,long a4,long a5)
{
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile("svc #0" : "+r"(x0)
            : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5)
            : "memory","cc");
    return x0; // >=0 成功；<0 == -errno
}

// ---- Encrypted SVC thunk (XOR SVCCALL_XOR_KEY) ----
// Plain bytes (little-endian):
//   e8 03 00 aa   mov x8, x0
//   e0 03 01 aa   mov x0, x1
//   e1 03 02 aa   mov x1, x2
//   e2 03 03 aa   mov x2, x3
//   e3 03 04 aa   mov x3, x4
//   e4 03 05 aa   mov x4, x5
//   e5 03 06 aa   mov x5, x6
//   01 00 00 d4   svc #0
//   c0 03 5f d6   ret
static const unsigned char k_thunk_enc[] = {
        // 每个字节 = plain ^ SVCCALL_XOR_KEY (默认 0xA5)
        0x4d,0xa6,0xa5,0x0f, 0x45,0xa6,0xa4,0x0f,
        0x44,0xa6,0xa7,0x0f, 0x47,0xa6,0xa6,0x0f,
        0x46,0xa6,0xa1,0x0f, 0x41,0xa6,0xa0,0x0f,
        0x40,0xa6,0xa3,0x0f, 0xa4,0xa5,0xa5,0x71,
        0x65,0xa6,0xfa,0x73
};

typedef long (*thunk_fn_t)(long, long,long,long,long,long,long);

long svccall(long nr, ...)
{
    // 收集最多 6 个变参（AArch64 下变参寄存器就是 x1..x6）
    long a[6] = {0,0,0,0,0,0};
    va_list ap;
    va_start(ap, nr);
    for (int i = 0; i < 6; i++)
        a[i] = va_arg(ap, long);
    va_end(ap);

    // 1) 匿名映射 1 页（RW）
    void *code = (void *) __svc6(__NR_mmap,
                                 0L, (long)SVCCALL_PAGE_SIZE,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                 -1L, 0L);
    if ((long) code < 0) {
#if SVCCALL_SET_ERRNO
        long rv = (long) code;
        if ((unsigned long) rv >= (unsigned long) -4095) {
            if (__set_errno_internal) __set_errno_internal((int) -rv);
            return -1;
        }
#endif
        return (long) code; // raw -errno
    }

    // 2) XOR 解密到该页
    volatile unsigned char *p = (volatile unsigned char *) code;
    for (unsigned i = 0; i < sizeof(k_thunk_enc); i++)
        p[i] = (unsigned char) (k_thunk_enc[i] ^ (unsigned char) SVCCALL_XOR_KEY);

    // 3) 刷 I-cache
    __builtin___clear_cache((char*) code, (char*) code + sizeof(k_thunk_enc));

    // 4) 切 RX
    long mp = __svc6(__NR_mprotect, (long) code, (long)SVCCALL_PAGE_SIZE,
                     PROT_READ | PROT_EXEC, 0L,0L,0L);
    if (mp < 0) {
        __svc6(__NR_munmap, (long) code, (long)SVCCALL_PAGE_SIZE, 0L,0L,0L,0L);
#if SVCCALL_SET_ERRNO
        if ((unsigned long) mp >= (unsigned long) -4095) {
            if (__set_errno_internal) __set_errno_internal((int) -mp);
            return -1;
        }
#endif
        return mp;
    }

    // 5) 调用（不经 libc）：x0=nr, x1..x6=arg
    thunk_fn_t fn = (thunk_fn_t) code;
    long rv = fn(nr, a[0], a[1], a[2], a[3], a[4], a[5]);

    // 6) 擦痕迹：回 RW → 覆盖 → 刷 I-cache → 置 NONE → 释放
    __svc6(__NR_mprotect, (long) code, (long)SVCCALL_PAGE_SIZE, PROT_READ | PROT_WRITE, 0L,0L,0L);
    for (unsigned i = 0; i < sizeof(k_thunk_enc); i++) p[i] = 0;
    __builtin___clear_cache((char*) code, (char*) code + sizeof(k_thunk_enc));
    __svc6(__NR_mprotect, (long) code, (long)SVCCALL_PAGE_SIZE, PROT_NONE, 0L,0L,0L);
    __svc6(__NR_munmap, (long) code, (long)SVCCALL_PAGE_SIZE, 0L,0L,0L,0L);

#if SVCCALL_SET_ERRNO
    // 兼容行为：失败时返回 -1 并设置 errno
    if ((unsigned long) rv >= (unsigned long) -4095) {
        if (__set_errno_internal) __set_errno_internal((int) -rv);
        return -1;
    }
#endif
    return rv; // 默认 raw：<0 == -errno
}
