// fastsink.h — 超轻量本地高频落盘（Android NDK / Linux）
// 用法：
//   #define FASTSINK_IMPLEMENTATION
//   #include "fastsink.h"
//   fastsink_open("/data/data/<pkg>/files/qbdi_trace.log", /*truncate=*/1);
//   fastsink_enable_timestamp(1);
//   fastsink_set_auto_nl(1);           // 建议：自动补换行
//   // fastsink_set_crlf(1);           // 如需 Windows 旧记事本兼容
//   fastsink_writefln("hello %d", 42);
//   fastsink_close();

#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 打开/关闭
int  fastsink_open(const char* path, int truncate_file);
void fastsink_close(void);

// 原始写入（返回写入字节数；失败 <0）
long fastsink_write(const void* data, size_t len);

// printf 风格写入（不强制换行）
int  fastsink_writef(const char* fmt, ...);

// 可选项
void fastsink_enable_timestamp(int enable);   // 每条前加 [sec.us]
void fastsink_set_prefix(const char* pfx);    // 每条固定前缀（可为 NULL）
int  fastsink_flush(void);                    // 手动 fsync

// —— 新增：换行控制 & 便捷 API ——
void fastsink_set_auto_nl(int enable);        // 自动在行尾补换行（默认关）
void fastsink_set_crlf(int enable);           // 换行风格：0=\n(默认) 1=\r\n
int  fastsink_writefln(const char* fmt, ...); // printf 风格，强制换行
int  fastsink_writeln(const void* data, size_t len); // 原始数据，强制换行

#ifdef __cplusplus
}
#endif


// =================== 实 现 区（单 TU 定义一次） ===================
#ifdef FASTSINK_IMPLEMENTATION

#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>   // writev
#include <stdio.h>

#ifndef FASTSINK_TLS_BUFSZ
#define FASTSINK_TLS_BUFSZ 4096   // 每次格式化最大长度（可调）
#endif

#ifndef FASTSINK_USE_MUTEX
// 如需“整行严格原子”（多线程强序），编译时 -DFASTSINK_USE_MUTEX=1
#define FASTSINK_USE_MUTEX 0
#endif

#if FASTSINK_USE_MUTEX
#include <pthread.h>
#endif

#if defined(__cplusplus)
#define FASTSINK_TLS thread_local
#elif defined(__GNUC__)
#define FASTSINK_TLS __thread
#else
  #define FASTSINK_TLS /* no TLS */
#endif

static int         g_fast_fd  = -1;
static int         g_ts       = 0;          // 时间戳开关
static const char* g_prefix   = NULL;       // 行前缀
static int         g_auto_nl  = 0;          // 自动补换行
static int         g_crlf     = 0;          // 0:\n 1:\r\n

#if FASTSINK_USE_MUTEX
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define FS_LOCK()   pthread_mutex_lock(&g_mu)
#define FS_UNLOCK() pthread_mutex_unlock(&g_mu)
#else
#define FS_LOCK()   ((void)0)
#define FS_UNLOCK() ((void)0)
#endif

static inline int _fs_open(const char* path, int trunc) {
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC | O_APPEND;
    if (trunc) flags |= O_TRUNC;
    int fd = open(path, flags, 0644);
    return fd;
}

int fastsink_open(const char* path, int truncate_file) {
    if (!path || !*path) return -1;
    FS_LOCK();
    if (g_fast_fd >= 0) { FS_UNLOCK(); return 0; }
    g_fast_fd = _fs_open(path, truncate_file ? 1 : 0);
    int ret = (g_fast_fd >= 0) ? 0 : -1;
    FS_UNLOCK();
    return ret;
}

void fastsink_close(void) {
    FS_LOCK();
    if (g_fast_fd >= 0) { close(g_fast_fd); g_fast_fd = -1; }
    FS_UNLOCK();
}

void fastsink_enable_timestamp(int enable) { g_ts = (enable != 0); }
void fastsink_set_prefix(const char* pfx)  { g_prefix = pfx; }
void fastsink_set_auto_nl(int enable)      { g_auto_nl = (enable != 0); }
void fastsink_set_crlf(int enable)         { g_crlf    = (enable != 0); }

int fastsink_flush(void) {
    FS_LOCK();
    int r = (g_fast_fd >= 0) ? fsync(g_fast_fd) : -1;
    FS_UNLOCK();
    return r;
}

static inline long _write_full(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return -1;
    }
    return (long)off;
}

static inline long _write_fullv(int fd, const struct iovec* iov, int iovcnt) {
    struct iovec vec[3];
    for (int i=0;i<iovcnt;i++){ vec[i]=iov[i]; }
    int left = iovcnt;
    while (left > 0) {
        ssize_t n = writev(fd, vec, left);
        if (n > 0) {
            size_t w = (size_t)n;
            int k = 0;
            while (k < left && w >= vec[k].iov_len) { w -= vec[k].iov_len; k++; }
            if (k > 0) {
                for (int i=0;i<left-k;i++) vec[i] = vec[i+k];
                left -= k;
            }
            if (w > 0) { vec[0].iov_base = (char*)vec[0].iov_base + w; vec[0].iov_len -= w; }
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return -1;
    }
    return 0;
}

long fastsink_write(const void* data, size_t len) {
    if (g_fast_fd < 0 || !data || len == 0) return -1;

#if FASTSINK_USE_MUTEX
    FS_LOCK();
#endif
    long r;
    if (!g_auto_nl) {
        r = _write_full(g_fast_fd, data, len);
    } else {
        const char* nl = g_crlf ? "\r\n" : "\n";
        char last = ((const char*)data)[len-1];
        int has_nl = (last == '\n') || (g_crlf && len>=2 &&
                                        ((const char*)data)[len-2]=='\r' && last=='\n');
        if (has_nl) {
            r = _write_full(g_fast_fd, data, len);
        } else {
            struct iovec iov[2] = {
                    { .iov_base = (void*)data, .iov_len = len },
                    { .iov_base = (void*)nl,   .iov_len = (size_t)(g_crlf ? 2 : 1) }
            };
            r = (_write_fullv(g_fast_fd, iov, 2) == 0) ? (long)(len + iov[1].iov_len) : -1;
        }
    }
#if FASTSINK_USE_MUTEX
    FS_UNLOCK();
#endif
    return r;
}

int fastsink_writef(const char* fmt, ...) {
    if (g_fast_fd < 0 || fmt == NULL) return -1;

    FASTSINK_TLS static char tlsbuf[FASTSINK_TLS_BUFSZ];
    char*  out = tlsbuf;
    size_t cap = sizeof(tlsbuf);
    size_t cur = 0;

    // [时间戳] 与 前缀
    if (g_ts) {
        struct timespec ts;
#if defined(CLOCK_REALTIME_COARSE)
        clock_gettime(CLOCK_REALTIME_COARSE, &ts);
#else
        clock_gettime(CLOCK_REALTIME, &ts);
#endif
        int k = snprintf(out + cur, cap - cur, "[%lld.%06ld] ",
                         (long long)ts.tv_sec, ts.tv_nsec/1000);
        if (k > 0) cur += (size_t)((k < (int)(cap-cur)) ? k : (int)(cap-cur ? cap-cur-1 : 0));
    }
    if (g_prefix && *g_prefix) {
        int k = snprintf(out + cur, cap - cur, "%s", g_prefix);
        if (k > 0) cur += (size_t)((k < (int)(cap-cur)) ? k : (int)(cap-cur ? cap-cur-1 : 0));
    }

    // 正文
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + cur, cap - cur, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= cap - cur) n = (int)(cap - cur - 1);
    cur += (size_t)n;

    // 自动补换行（尽量仍一次 write）
    if (g_auto_nl) {
        const char* nl = g_crlf ? "\r\n" : "\n";
        size_t nl_len  = g_crlf ? 2 : 1;
        int has_nl = (cur>0 && out[cur-1]=='\n') ||
                     (g_crlf && cur>1 && out[cur-2]=='\r' && out[cur-1]=='\n');
        if (!has_nl) {
            if (cur + nl_len < cap) {
                memcpy(out + cur, nl, nl_len);
                cur += nl_len;
            } else {
                // 缓冲不够：退化为两次写
                long r1 = _write_full(g_fast_fd, out, cur);
                long r2 = _write_full(g_fast_fd, nl, nl_len);
                return (r1>=0 && r2>=0) ? (int)(r1 + r2) : -1;
            }
        }
    }

#if FASTSINK_USE_MUTEX
    FS_LOCK();
    long r = _write_full(g_fast_fd, out, cur);
    FS_UNLOCK();
#else
    long r = _write_full(g_fast_fd, out, cur);
#endif
    return (r >= 0) ? (int)r : -1;
}

// printf 风格：强制换行（不依赖 g_auto_nl）
int fastsink_writefln(const char* fmt, ...) {
    if (g_fast_fd < 0 || fmt == NULL) return -1;

    FASTSINK_TLS static char tlsbuf[FASTSINK_TLS_BUFSZ];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(tlsbuf, sizeof(tlsbuf), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    size_t len = (n < (int)sizeof(tlsbuf)) ? (size_t)n : (sizeof(tlsbuf)-1);

    const char* nl = g_crlf ? "\r\n" : "\n";
    struct iovec iov[2] = {
            { .iov_base = tlsbuf, .iov_len = len },
            { .iov_base = (void*)nl, .iov_len = (size_t)(g_crlf ? 2 : 1) }
    };

#if FASTSINK_USE_MUTEX
    FS_LOCK();
    long r = (_write_fullv(g_fast_fd, iov, 2) == 0) ? (long)(len + iov[1].iov_len) : -1;
    FS_UNLOCK();
#else
    long r = (_write_fullv(g_fast_fd, iov, 2) == 0) ? (long)(len + iov[1].iov_len) : -1;
#endif
    return (r >= 0) ? (int)r : -1;
}

// 原始数据：强制换行（不依赖 g_auto_nl）
int fastsink_writeln(const void* data, size_t len) {
    if (g_fast_fd < 0 || !data) return -1;
    const char* nl = g_crlf ? "\r\n" : "\n";
    struct iovec iov[2] = {
            { .iov_base = (void*)data, .iov_len = len },
            { .iov_base = (void*)nl,   .iov_len = (size_t)(g_crlf ? 2 : 1) }
    };

#if FASTSINK_USE_MUTEX
    FS_LOCK();
    long r = (_write_fullv(g_fast_fd, iov, 2) == 0) ? (long)(len + iov[1].iov_len) : -1;
    FS_UNLOCK();
#else
    long r = (_write_fullv(g_fast_fd, iov, 2) == 0) ? (long)(len + iov[1].iov_len) : -1;
#endif
    return (r >= 0) ? (int)r : -1;
}

#endif // FASTSINK_IMPLEMENTATION
