#pragma once
// gumx.h — Frida Gum Hook Helper (C99, no GumModuleDetails)

#include "frida-gum.h"
//#include <glib.h>
#include "Logger.h"   // 使用你的日志

// 映射到你的 Logger
#define GUMX_LOGI(...) LOGD(__VA_ARGS__)
#define GUMX_LOGW(...) LOGD(__VA_ARGS__)
#define GUMX_LOGE(...) LOGE(__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*GumXOnEnter)(GumInvocationContext *ic, gpointer user_data);
typedef void (*GumXOnLeave)(GumInvocationContext *ic, gpointer user_data);

typedef struct {
    GumInvocationListener *listener;  // 用于后续 unhook
    gpointer               target;    // 被钩地址（只读）
} GumXHook;

void gumx_init(void);
void gumx_shutdown(void);

// 按符号名装钩：modname 可为 NULL（不限定模块）
GumInvocationListener * gumx_hook_symbol(
        const char *modname,
        const char *symbol,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor,
        GumXHook *out_hook,   // 可为 NULL
        GError **error);      // 可为 NULL

// 按 RVA 装钩：addr = base(modname) + rva（base 拿不到则从 /proc/self/maps 推断）
GumInvocationListener * gumx_hook_rva(
        const char *modname,
        GumAddress rva,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor,
        GumXHook *out_hook,
        GError **error);

// 批量（同一事务）
GPtrArray * gumx_hook_symbols_batch(
        const char *modname,
        const char * const *symbols,
        gsize count,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor);

void gumx_unhook(GumInvocationListener *listener);

#ifdef __cplusplus
}
#endif
