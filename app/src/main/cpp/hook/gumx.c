// gumx.c — Frida Gum Hook Helper (C99, no GumModuleDetails)
#include "gumx.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>     // fgets, sscanf
#include <stdlib.h>    // strtoull
#include <errno.h>

static gboolean g_inited = FALSE;
static GumInterceptor *g_interceptor = NULL;

static void gumx_once_init(void) {
    if (g_inited) return;
    gum_init_embedded();
    g_interceptor = gum_interceptor_obtain();
    g_inited = TRUE;
}

void gumx_init(void) { gumx_once_init(); }
void gumx_shutdown(void) { /* 通常不在此强退 frida-gum 运行时 */ }

/* ---------- 辅助：/proc/self/maps 查 so 的可执行段基址 ---------- */
static GumAddress gumx_find_module_base_from_maps(const char *hint) {
    if (hint == NULL || *hint == '\0') return 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        GUMX_LOGW("[GumX] open /proc/self/maps failed: %d", errno);
        return 0;
    }

    char line[2048];
    GumAddress best = 0;
    while (fgets(line, sizeof(line), fp)) {
        // 形如: 7f1a2c0000-7f1a2e0000 r-xp ... /apex/.../libc.so
        unsigned long long start = 0ULL;
        char perms[8] = {0};
        char path[1024] = {0};

        // 路径不一定总有，先尝试解析
        // 注意: %s 会吃到换行前的路径（若存在）
        int n = sscanf(line, "%llx-%*llx %7s %*s %*s %*s %1023s", &start, perms, path);
        if (n < 2) continue; // 起码要有地址和 perms

        // 需要可执行段
        if (strchr(perms, 'x') == NULL) continue;

        // 无路径行（匿名段）忽略
        if (n < 3 || path[0] == '\0' || path[0] != '/') continue;

        // 后缀匹配（兼容绝对路径）
        size_t hl = strlen(hint), pl = strlen(path);
        if ((hl <= pl && strcmp(path + (pl - hl), hint) == 0) ||
            strcmp(path, hint) == 0) {
            best = (GumAddress) start;
            break; // 命中即取（通常第一段就是 text 段基址）
        }
    }
    fclose(fp);
    return best;
}

/* ---------- 辅助：宽松找模块对象（仅用名字，不枚举） ---------- */
static GumModule * gumx_find_module_relaxed(const char *hint_name) {
    if (hint_name && *hint_name) {
        GumModule *mod = gum_process_find_module_by_name(hint_name);
        if (mod != NULL) return mod;
    }
    return NULL;
}

/* ---------- 符号解析：导出 -> 符号表 -> 全局 -> dlsym ---------- */
static GumAddress gumx_resolve_symbol(const char *modname, const char *symbol) {
    GumAddress addr = 0;
    GumModule *mod = gumx_find_module_relaxed(modname);

    if (mod != NULL) {
        gum_module_ensure_initialized(mod);
        addr = gum_module_find_export_by_name(mod, symbol);
        if (addr == 0)
            addr = gum_module_find_symbol_by_name(mod, symbol);
    }
    if (addr == 0)
        addr = gum_module_find_global_export_by_name(symbol);
    if (addr == 0) {
        void *p = dlsym(RTLD_DEFAULT, symbol);
        if (p == NULL) p = dlsym(RTLD_NEXT, symbol);
        addr = (GumAddress) p;
    }
    return addr;
}

/* ---------- 通用 attach ---------- */
static GumInvocationListener * gumx_attach_at_addr(
        gpointer target,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor,
        GumXHook *out_hook,
        GError **error)
{
    if (target == NULL) {
        if (error) g_set_error(error, g_quark_from_static_string("GumX"), 1,
                               "target address is NULL");
        return NULL;
    }
    gumx_once_init();

    GumInvocationListener *lsn =
            gum_make_call_listener(on_enter, on_leave, user_data, user_data_dtor);

    gum_interceptor_begin_transaction(g_interceptor);
    gum_interceptor_attach(g_interceptor, target, lsn,
            /*func_data*/ NULL, GUM_ATTACH_FLAGS_NONE);
    gum_interceptor_end_transaction(g_interceptor);

    if (out_hook) {
        out_hook->listener = lsn;
        out_hook->target = target;
    }
    return lsn;
}

/* ---------- 对外：按符号 ---------- */
GumInvocationListener * gumx_hook_symbol(
        const char *modname,
        const char *symbol,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor,
        GumXHook *out_hook,
        GError **error)
{
    if (symbol == NULL || *symbol == 0) {
        if (error) g_set_error(error, g_quark_from_static_string("GumX"), 2,
                               "symbol name is empty");
        return NULL;
    }

    GumAddress a = gumx_resolve_symbol(modname, symbol);
    if (a == 0) {
        if (error) g_set_error(error, g_quark_from_static_string("GumX"), 3,
                               "symbol '%s' not found in '%s' (and global)",
                               symbol, modname ? modname : "(any)");
        return NULL;
    }

    GUMX_LOGI("[GumX] resolved %s!%s -> %p", modname ? modname : "(any)", symbol, (void*)a);
    return gumx_attach_at_addr(GSIZE_TO_POINTER(a),
                               on_enter, on_leave, user_data, user_data_dtor,
                               out_hook, error);
}

/* ---------- 对外：按 RVA ---------- */
GumInvocationListener * gumx_hook_rva(
        const char *modname,
        GumAddress rva,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor,
        GumXHook *out_hook,
        GError **error)
{
    if (modname == NULL || *modname == 0) {
        if (error) g_set_error(error, g_quark_from_static_string("GumX"), 4,
                               "module name is required for RVA hooking");
        return NULL;
    }

    GumAddress base = 0;
    GumModule *mod = gumx_find_module_relaxed(modname);
    if (mod) {
        gum_module_ensure_initialized(mod);
        base = gum_module_get_range(mod)->base_address;
    } else {
        base = gumx_find_module_base_from_maps(modname); // 退回 /proc/self/maps
    }

    if (base == 0) {
        if (error) g_set_error(error, g_quark_from_static_string("GumX"), 5,
                               "failed to find base of module '%s'", modname);
        return NULL;
    }

    GumAddress addr = base + rva;
    GUMX_LOGI("[GumX] RVA hook %s: base=%p rva=0x%lx -> %p",
              modname, (void*)base, (unsigned long) rva, (void*)addr);

    return gumx_attach_at_addr(GSIZE_TO_POINTER(addr),
                               on_enter, on_leave, user_data, user_data_dtor,
                               out_hook, error);
}

/* ---------- 批量 ---------- */
GPtrArray * gumx_hook_symbols_batch(
        const char *modname,
        const char * const *symbols,
        gsize count,
        GumXOnEnter on_enter,
        GumXOnLeave on_leave,
        gpointer user_data,
        GDestroyNotify user_data_dtor)
{
    gumx_once_init();

    // 不设置 free_func，避免和外部 gumx_unhook 重复释放
    GPtrArray *out = g_ptr_array_new();

    gum_interceptor_begin_transaction(g_interceptor);
    for (gsize i = 0; i < count; i++) {
        const char *sym = symbols[i];
        GumAddress a = gumx_resolve_symbol(modname, sym);
        if (a == 0) {
            GUMX_LOGW("[GumX] resolve failed: %s!%s", modname ? modname : "(any)", sym);
            continue;
        }
        GumInvocationListener *lsn =
                gum_make_call_listener(on_enter, on_leave, user_data, user_data_dtor);
        gum_interceptor_attach(g_interceptor, GSIZE_TO_POINTER(a), lsn,
                               NULL, GUM_ATTACH_FLAGS_NONE);
        g_ptr_array_add(out, lsn);
        GUMX_LOGI("[GumX] hooked %s!%s @ %p",
                  modname ? modname : "(any)", sym, (void*) a);
    }
    gum_interceptor_end_transaction(g_interceptor);
    return out;
}

/* ---------- 解除 ---------- */
void gumx_unhook(GumInvocationListener *listener) {
    if (!listener || !g_interceptor) return;
    gum_interceptor_detach(g_interceptor, listener);
    g_object_unref(listener);
}
