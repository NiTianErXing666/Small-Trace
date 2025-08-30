// Created by Administrator on 2025/8/28.

#include <jni.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include "frida-gum.h"
#include "Logger.h"
#include "gumx.h"

//// 可选：测试期关 Fortify，便于观察自己 TU 的 open 是否走 __open_2
//#undef _FORTIFY_SOURCE
//
//typedef enum {
//    HOOK_OPEN = 1,
//    HOOK_OPEN64,
//    HOOK_OPEN2,     // __open_2 (FORTIFY)
//    HOOK_OPENAT,
//    HOOK_OPENAT64   // __openat64
//} HookId;
//
//static void on_enter (GumInvocationContext *ic, gpointer user_data);
//static void on_leave (GumInvocationContext *ic, gpointer user_data);
//
//static gpointer find_sym(const char* modname, const char* sym) {
//    GumAddress addr = 0;
//
//    if (modname && *modname) {
//        // 先按名字拿模块对象（不会重复加载）
//        GumModule* mod = gum_process_find_module_by_name(modname);
//        if (mod != NULL) {
//            gum_module_ensure_initialized(mod);
//            // 先从导出表找
//            addr = gum_module_find_export_by_name(mod, sym);
//            // 导出没找到就从符号表再试（strip 的库可能拿不到）
//            if (addr == 0)
//                addr = gum_module_find_symbol_by_name(mod, sym);
//        }
//    }
//
//    // 仍未找到：进程里全局导出里找（可能命中“别的库”的同名符号）
//    if (addr == 0)
//        addr = gum_module_find_global_export_by_name(sym);
//
//    // 最后兜底：dlsym
//    if (addr == 0) {
//        void* p = dlsym(RTLD_NEXT, sym);
//        if (p == NULL) p = dlsym(RTLD_DEFAULT, sym);
//        addr = (GumAddress)p;
//    }
//
//    return GSIZE_TO_POINTER(addr);
//}
//
//static GumInterceptor *itc = NULL;
//static GumInvocationListener *lsn = NULL;
//static bool is_init = false;
//
//static void init_gum_once(void) {
//    gum_init_embedded();
//    itc = gum_interceptor_obtain();
//    // 保险：确保当前线程不是被忽略状态（一般默认不会被忽略）
//    // 如果你的 gum 版本没有该 API，可注释掉这行
//    // gum_interceptor_unignore_current_thread(itc);
//
//    lsn = gum_make_call_listener(on_enter, on_leave, NULL, NULL);
//}
// 你的 enter/leave
static void on_enter(GumInvocationContext *ic, gpointer ud) {
    // __openat(int dirfd, const char* pathname, int flags, mode_t mode[可选])
    int dirfd = GPOINTER_TO_INT(gum_invocation_context_get_nth_argument(ic, 0));
    const char *path = (const char*) gum_invocation_context_get_nth_argument(ic, 1);
    int flags = GPOINTER_TO_INT(gum_invocation_context_get_nth_argument(ic, 2));

    if (flags & O_CREAT) {
        unsigned long mode = (unsigned long) gum_invocation_context_get_nth_argument(ic, 3);
        LOGD("[*] __openat(dirfd=%d, \"%s\", 0x%x, 0%lo)", dirfd, path ? path : "(null)", flags, mode);
    } else {
        LOGD("[*] __openat(dirfd=%d, \"%s\", 0x%x)", dirfd, path ? path : "(null)", flags);
    }
}

static void on_leave(GumInvocationContext *ic, gpointer ud) {
    intptr_t fd = (intptr_t) gum_invocation_context_get_return_value(ic);
    LOGD("[*] __openat -> fd=%ld", (long) fd);

}
JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1gum(JNIEnv *env, jobject thiz) {
//    if (is_init) return;
//    is_init = true;
//
//    init_gum_once();
//
//    struct { const char* sym; HookId id; } targets[] = {
//            { "open",        HOOK_OPEN    },
//            { "_openat",      HOOK_OPEN64  },   // LP64 上通常等价，但加上更稳
//            { "__open_2",    HOOK_OPEN2   },   // FORTIFY 入口
//            { "openat",      HOOK_OPENAT  },
//            { "__openat64",  HOOK_OPENAT64},
//    };
//
//    gum_interceptor_begin_transaction(itc);
//    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
//        gpointer addr = find_sym("libc.so", targets[i].sym);
//        if (addr) {
//            LOGD("[*] hook %s @ %p", targets[i].sym, addr);
//            gum_interceptor_attach(itc, addr, lsn,
//                                   GSIZE_TO_POINTER(targets[i].id), GUM_ATTACH_FLAGS_NONE);
//        } else {
//            LOGW("[!] resolve failed: %s", targets[i].sym);
//        }
//    }
//    gum_interceptor_end_transaction(itc);

// 初始化 + 一行装钩
    gumx_init();
    GError *err = NULL;
    GumXHook hk;
    GumInvocationListener *lsn = gumx_hook_symbol("libc.so", "__openat",
                                                  on_enter, on_leave, NULL, NULL, &hk, &err);
    if (!lsn) {
        LOGE("hook open failed: %s", err ? err->message : "(unknown)");
        if (err) g_error_free(err);
    }
}

//static void on_enter (GumInvocationContext *ic, gpointer user_data) {
//    (void) user_data;
//    HookId id = (HookId) GUM_IC_GET_FUNC_DATA (ic, HookId);
//
//    switch (id) {
//        case HOOK_OPEN:
//        case HOOK_OPEN64:
//        case HOOK_OPEN2: {
//            const char *path = (const char *) gum_invocation_context_get_nth_argument (ic, 0);
//            int flags = GPOINTER_TO_INT (gum_invocation_context_get_nth_argument (ic, 1));
//            if (flags & O_CREAT) {
//                unsigned long mode = (unsigned long) gum_invocation_context_get_nth_argument (ic, 2);
//                LOGE("[*] %s(\"%s\", 0x%x, 0%lo)",
//                     (id==HOOK_OPEN2?"__open_2":(id==HOOK_OPEN64?"open64":"open")),
//                     path?path:"(null)", flags, mode);
//            } else {
//                LOGE("[*] %s(\"%s\", 0x%x)",
//                     (id==HOOK_OPEN2?"__open_2":(id==HOOK_OPEN64?"open64":"open")),
//                     path?path:"(null)", flags);
//            }
//            break;
//        }
//        case HOOK_OPENAT:
//        case HOOK_OPENAT64: {
//            int dfd = GPOINTER_TO_INT (gum_invocation_context_get_nth_argument (ic, 0));
//            const char *path = (const char *) gum_invocation_context_get_nth_argument (ic, 1);
//            int flags = GPOINTER_TO_INT (gum_invocation_context_get_nth_argument (ic, 2));
//            if (flags & O_CREAT) {
//                unsigned long mode = (unsigned long) gum_invocation_context_get_nth_argument (ic, 3);
//                LOGE("[*] %s(%d, \"%s\", 0x%x, 0%lo)",
//                     (id==HOOK_OPENAT64?"__openat64":"openat"),
//                     dfd, path?path:"(null)", flags, mode);
//            } else {
//                LOGE("[*] %s(%d, \"%s\", 0x%x)",
//                     (id==HOOK_OPENAT64?"__openat64":"openat"),
//                     dfd, path?path:"(null)", flags);
//            }
//            break;
//        }
//        default:
//            break;
//    }
//}
//
//static void on_leave (GumInvocationContext *ic, gpointer user_data) {
//    (void) user_data;
//    HookId id = (HookId) GUM_IC_GET_FUNC_DATA (ic, HookId);
//    intptr_t rv = (intptr_t) gum_invocation_context_get_return_value (ic);
//
//    switch (id) {
//        case HOOK_OPEN:
//        case HOOK_OPEN64:
//        case HOOK_OPEN2:
//        case HOOK_OPENAT:
//        case HOOK_OPENAT64:
//            LOGE("[*] -> fd=%ld", (long) rv);
//            break;
//        default:
//            break;
//    }
//}

JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1open(JNIEnv *env, jobject thiz) {
    // 1) 常规 open（可能走 __open_2）
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) close(fd);
    LOGD("test_open: open => fd=%d", fd);

    // 2) 直接 syscall openat（验证 openat 线）
    // 如果你有 <sys/syscall.h>，可写成 syscall(__NR_openat, AT_FDCWD, path, flags, 0)
    // 这里简单用 openat 封装：
    int fd2 = openat(AT_FDCWD, "/proc/self/cmdline", O_RDONLY);
    if (fd2 >= 0) close(fd2);
    LOGD("test_open: openat => fd=%d", fd2);
}
