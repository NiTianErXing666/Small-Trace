// --- 原有的头文件部分 ---

#define FASTSINK_IMPLEMENTATION
#include "fastsink.h"
#include "gumx.h"
#include "frida-gum.h"
#include "QBDI.h"
#include "sosym_c.h"   // ★ 新增：你的地址→符号解析器

#include <android/log.h>
#include <vector>
#include <string>
#include <cstring>
#include <cinttypes>
#include <cctype>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#define TAG "GQB-GUMX"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)



// ----------------- 全局/单例 -----------------
static thread_local struct VmTLS {
    bool inited = false;
    QBDI::VM vm;
    struct TraceCtx {
        QBDI::rword fn = 0;
        int   depth = 0;
        bool  entered = false;
        uint64_t preX[31]{};
        uint64_t iaVA = 0, iaRVA = 0;
        char     iaText[128]{};
    } trace;
    uint8_t* stack = nullptr;
} g_tls;

static sosym_handle* g_sym = nullptr; // ★ sosym 句柄（全进程共用）

// --- 工具函数部分 ---
static inline uint64_t untag_addr(uint64_t a){
#if defined(__aarch64__)
    return a & 0x00FFFFFFFFFFFFFFull;
#else
    return a;
#endif
}
static inline int selfmem(){
    static int fd = -2;
    if (fd == -2) { fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC); if (fd < 0) fd = -1; }
    return fd;
}
static inline size_t safe_read(uint64_t addr, void* buf, size_t len){
    uint64_t ua = untag_addr(addr);
    int fd = selfmem();
    if (fd >= 0) {
        ssize_t n = pread(fd, buf, len, (off_t)ua);
        return (n > 0) ? (size_t)n : 0;
    }
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t a = (uintptr_t)ua, end = (a & ~(uintptr_t)(ps - 1)) + (uintptr_t)ps;
    size_t m = (a + len > end) ? (size_t)(end - a) : len;
    if (!m) return 0;
    memcpy(buf, reinterpret_cast<const void*>(a), m);
    return m;
}
static inline void hexdump_window(uint64_t center, size_t window = 0x80){
    uint64_t c = untag_addr(center);
    uint64_t start = (c & ~0xFULL) - (window / 2);
    std::vector<uint8_t> buf(window);
    size_t got = safe_read(start, buf.data(), buf.size());
    if (got == 0) return;
    auto line = [](uint64_t addr, const uint8_t* p, size_t n, bool mark){
        static const char* H="0123456789ABCDEF";
        char hex[16 * 3 + 1]; size_t hp = 0;
        for (size_t j = 0; j < 16; j++) {
            if (j < n) {
                uint8_t b = p[j];
                hex[hp++] = H[b >> 4];
                hex[hp++] = H[b & 0xF];
            } else {
                hex[hp++] = ' ';
                hex[hp++] = ' ';
            }
            hex[hp++] = ' ';
        }
        hex[hp ? hp - 1 : 0] = '\0';
        char asc[17]; for (size_t j = 0; j < 16; j++) asc[j] = (j < n && p[j] >= 0x20 && p[j] <= 0x7E) ? (char)p[j] : ' '; asc[16] = '\0';
        fastsink_writefln("%c%016" PRIx64 "  %s |%s|", mark ? '*' : ' ', addr, hex, asc);
    };
    for (uint64_t a = start; a < start + got; a += 16) {
        size_t n = ((start + got - a) < 16) ? (size_t)(start + got - a) : 16;
        bool mark = (c >= a && c < a + 16);
        line(a, &buf[(size_t)(a - start)], n, mark);
    }
}

// --- AArch64 通用寄存器读取（旧版 GPRState 结构） ---
static inline uint64_t getX(const QBDI::GPRState* g, int idx){
    switch(idx){
        case  0: return g->x0; case  1: return g->x1; case  2: return g->x2; case  3: return g->x3;
        case  4: return g->x4; case  5: return g->x5; case  6: return g->x6; case  7: return g->x7;
        case  8: return g->x8; case  9: return g->x9; case 10: return g->x10; case 11: return g->x11;
        case 12: return g->x12; case 13: return g->x13; case 14: return g->x14; case 15: return g->x15;
        case 16: return g->x16; case 17: return g->x17; case 18: return g->x18; case 19: return g->x19;
        case 20: return g->x20; case 21: return g->x21; case 22: return g->x22; case 23: return g->x23;
        case 24: return g->x24; case 25: return g->x25; case 26: return g->x26; case 27: return g->x27;
        case 28: return g->x28; case 29: return g->x29; case 30: return g->lr;
        default: return 0;
    }
}
static inline const char* regName(int i){
    static const char* N[31]={"X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15","X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","X29","X30"};
    return (i>=0&&i<31)?N[i]:"X?";
}

// --------- 模块基址（只用 Gum API）---------
static inline GumAddress gumx_module_base_by_name(const char* modname) {
    if (modname == nullptr || *modname == '\0') return 0;
    GError* err = NULL;
    GumModule* mod = gum_module_load(modname, &err);
    if (mod == NULL) { if (err) g_clear_error(&err); return 0; }
    gum_module_ensure_initialized(mod);
    const GumMemoryRange* r = gum_module_get_range(mod);
    return (r != NULL) ? (GumAddress) r->base_address : 0;   // ★ 修正：返回 base，不是 size
}

// --------- 地址→(so, rva) 的简易回落解析 ---------
static inline bool addr_to_mod(uint64_t addr, const char** so_path, uint64_t* rva) {
    Dl_info dli{}; if (!dladdr((void*)addr, &dli) || !dli.dli_fbase) return false;
    if (so_path) *so_path = dli.dli_fname;
    if (rva) *rva = addr - (uint64_t)(uintptr_t)dli.dli_fbase;
    return true;
}

// --------- 尝试从“调用指令”的反汇编里抓取目标地址 ---------
static bool parse_call_target(const char* dis, const uint64_t preX[31], uint64_t& out) {
    if (!dis || !*dis) return false;

    // trim 前缀空白
    while (*dis==' ' || *dis=='\t') dis++;

    // 1) bl 0x....  /  bl 123456   /  bl <symbol>(不可解析为数值)
    if ((dis[0]=='b' || dis[0]=='B') && (dis[1]=='l' || dis[1]=='L')) {
        const char* p = dis + 2;
        while (*p==' '||*p=='\t') p++;
        // 立即数
        if (p[0]=='0' && (p[1]=='x' || p[1]=='X')) {
            char* end=nullptr;
            uint64_t v = strtoull(p, &end, 16);
            if (end && end>p) { out = v; return true; }
        } else if (std::isdigit((unsigned char)p[0])) {
            char* end=nullptr;
            uint64_t v = strtoull(p, &end, 10);
            if (end && end>p) { out = v; return true; }
        }
        // blr xN 的情况，下面会覆盖
    }

    // 2) blr x16 / blr x17 / blr x0...
    if ((dis[0]=='b'||dis[0]=='B') && (dis[1]=='l'||dis[1]=='L') && (dis[2]=='r'||dis[2]=='R')) {
        const char* p = dis + 3;
        while (*p==' '||*p=='\t' || *p==',') p++;
        if ((*p=='x'||*p=='X') && std::isdigit((unsigned char)p[1])) {
            int idx = 0; p++;
            while (std::isdigit((unsigned char)*p)) { idx = idx*10 + (*p-'0'); p++; }
            if (idx>=0 && idx<=30) { out = preX[idx]; return true; }
        }
    }
    return false;
}

// --- QBDI Trace 回调：onPre ---
static QBDI::VMAction onPre(QBDI::VM* vm, QBDI::GPRState* g, QBDI::FPRState*, void* u){
    auto* ctx = (decltype(g_tls.trace)*)u;
    const QBDI::InstAnalysis* ia = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY);
    if (!ia) return QBDI::VMAction::CONTINUE;

    // 进入首条指令时打印 ENTER
    if (!ctx->entered && ia->address == ctx->fn) {
        ctx->entered = true;
        ctx->depth   = 1;
        fastsink_writefln("====== ENTER 0x%" PRIx64 " (global) ======", (uint64_t)ctx->fn);
    }

    ctx->iaVA = ia->address;
    Dl_info dli {}; ctx->iaRVA = 0;
    if (dladdr((void*)ia->address, &dli) && dli.dli_fbase)
        ctx->iaRVA = ia->address - (uintptr_t)dli.dli_fbase;

    strncpy(ctx->iaText, ia->disassembly ? ia->disassembly : "", sizeof(ctx->iaText)-1);
    for (int i = 0; i < 31; i++) ctx->preX[i] = getX(g, i);

    if (ia->isCall) ctx->depth++;
    if (ia->isReturn) {
        if (ctx->depth > 0) ctx->depth--;
        if (ctx->entered && ctx->depth == 0)
            fastsink_writefln("======  LEAVE 0x%" PRIx64 " ======", (uint64_t)ctx->fn);
    }
    return QBDI::VMAction::CONTINUE;
}

// --- QBDI Trace 回调：onPost ---
static inline size_t ma_sz(const QBDI::MemoryAccess& ma){ return ma.size ? (size_t)ma.size : 8; }

static QBDI::VMAction onPost(QBDI::VM* vm, QBDI::GPRState* g, QBDI::FPRState*, void* u){
    auto* ctx = (decltype(g_tls.trace)*)u;

    // 指令打印（与之前一致）
    int changed=-1; uint64_t preV=0, postV=0;
    for (int i=0;i<31;i++){ uint64_t now=getX(g,i); if(now!=ctx->preX[i]){changed=i;preV=ctx->preX[i];postV=now;break;} }
    if (changed>=0) fastsink_writefln("0x%016" PRIx64 "\t0x%llx\t\t%s\t;%s=0x%llx -> 0x%llx",
                                      (uint64_t)ctx->iaVA, (unsigned long long)ctx->iaRVA, ctx->iaText,
                                      regName(changed),(unsigned long long)preV,(unsigned long long)postV);
    else             fastsink_writefln("0x%016" PRIx64 "\t0x%llx\t\t%s",
                                       (uint64_t)ctx->iaVA, (unsigned long long)ctx->iaRVA, ctx->iaText);

    // ★ 如果是调用指令：解析“被调地址”，打印符号（失败则打印 so+偏移）
    uint64_t target = 0;
    if (parse_call_target(ctx->iaText, ctx->preX, target) && target != 0) {
        const char* so_path = NULL; uint64_t rva = 0, fsz = 0;
        const char* fn = g_sym ? sosym_resolve_fast(g_sym, (uintptr_t)target, &so_path, &rva, &fsz) : NULL;
        if (fn) {
            fastsink_writefln("  CALL -> [%s] %s + 0x%llx (size=%llu) (target=0x%llx)",
                              so_path ? so_path : "(?)", fn,
                              (unsigned long long) rva,
                              (unsigned long long) fsz,
                              (unsigned long long) target);
        } else {
            const char* p = nullptr; uint64_t off=0;
            if (addr_to_mod(target, &p, &off))
                fastsink_writefln("  CALL -> [%s] + 0x%llx (target=0x%llx)", p?p:"(?)",
                                  (unsigned long long)off, (unsigned long long)target);
            else
                fastsink_writefln("  CALL -> 0x%llx", (unsigned long long)target);
        }
    }

    // 内存访问打印
    for (const auto& ma : vm->getInstMemoryAccess()){
        const char* rw = (ma.type & QBDI::MEMORY_WRITE)? "write":"read";
        size_t sz = ma_sz(ma);
        uint8_t b[8]{}; size_t want = (sz<=8?sz:8), got = safe_read((uint64_t)ma.accessAddress, b, want);
        char val[2*8+1]={0}; for(size_t i=0;i<got;i++) sprintf(val+i*2,"%02x", b[i]);
        fastsink_writefln("memory %s at 0x%" PRIx64 ", instruction address = 0x%" PRIx64 ", data size = %zu, data value = %s",
                          rw, (uint64_t)ma.accessAddress, (uint64_t)ctx->iaVA, sz, val);
        hexdump_window((uint64_t)ma.accessAddress);
    }
    return QBDI::VMAction::CONTINUE;
}

// --- VM 复用 ---
static bool tls_vm_init(){
    if (g_tls.inited) return true;
    QBDI::GPRState* s = g_tls.vm.getGPRState();
    if (!QBDI::allocateVirtualStack(s, 1u<<20, &g_tls.stack)) return false;
    g_tls.vm.instrumentAllExecutableMaps();
    if (g_tls.vm.addCodeCB(QBDI::InstPosition::PREINST,  onPre,  &g_tls.trace) == QBDI::INVALID_EVENTID) return false;
    if (!g_tls.vm.recordMemoryAccess(QBDI::MEMORY_READ | QBDI::MEMORY_WRITE)) return false;
    if (g_tls.vm.addCodeCB(QBDI::InstPosition::POSTINST, onPost, &g_tls.trace) == QBDI::INVALID_EVENTID) return false;
    g_tls.inited = true;
    return true;
}
static QBDI::rword run_under_qbdi(QBDI::rword fn, const std::vector<QBDI::rword>& args) {
    if (!tls_vm_init()){ fastsink_writefln("[gqb] VM init failed"); return 0; }
    g_tls.trace.fn = fn;
    g_tls.trace.entered = false;
    g_tls.trace.depth = 0;
    QBDI::rword ret=0;
    bool ok = g_tls.vm.call(&ret, fn, args);
    fastsink_writefln("[gqb] vm.call ok=%d, ret=0x%" PRIx64, (int)ok, (uint64_t)ret);
    return ret;
}

// --- gumx 集成 ---
typedef struct { int argc; void* target; } HookConf;

static void on_enter_bridge(GumInvocationContext* ic, gpointer user_data) {
    HookConf* cfg = (HookConf*)user_data;
    if (!cfg) return;
//#if defined(__aarch64__)
    std::vector<QBDI::rword> args;
    args.reserve((size_t)cfg->argc);
    for (int i = 0; i < cfg->argc; i++) { // ★ 不再限制 6 个；Frida 会处理寄存器/栈
        gpointer p = gum_invocation_context_get_nth_argument(ic, (guint)i);
        args.push_back((QBDI::rword)p);
    }
    QBDI::rword fn = (QBDI::rword) cfg->target;
    fastsink_writefln("[hook] target=%p argc=%d", (void*)fn, cfg->argc);
    QBDI::rword ret = run_under_qbdi(fn, args);
    LOGD("程序trace 运行完毕 ret %lx",ret);
//    gum_invocation_context_replace_return_value(ic, (gpointer) ret);
//#else
//    (void)ic; (void)cfg;
//#endif
}
static void on_leave_nop(GumInvocationContext*, gpointer){
    LOGD("on_leave_nop");
}

// ---------------- 对外接口 ----------------

// ★ 一键初始化：日志 + gumx + sosym(预载 hook so)。
extern "C"
void gqb_init_all(const char* log_path, const char* const* hook_so_names, int hook_so_count) {
    // sink
    gumx_init();
    fastsink_open(log_path ? log_path : "/data/local/tmp/gqb_trace.log", /*truncate=*/0);
    fastsink_enable_timestamp(1);
    fastsink_set_auto_nl(1);
    fastsink_set_prefix("TRACE ");

    // sosym
    if (!g_sym) g_sym = sosym_create();
    if (g_sym && hook_so_names && hook_so_count > 0) {
        int n = sosym_preload_by_names(g_sym, hook_so_names, hook_so_count);
        size_t so=0, fn=0; sosym_stats(g_sym, &so, &fn);
        ALOGI("sosym preloaded: %d new, total so=%zu, funcs=%zu", n, so, fn);
    } else {
        ALOGI("sosym ready (no preload list provided).");
    }
    ALOGI("gqb_init_all OK, log=%s", log_path ? log_path : "(default)");
}

// 兼容旧名
extern "C"
void gqb_init_sink(const char* path){ gqb_init_all(path, nullptr, 0); }

// 钩取符号
extern "C"
int gqb_hook_symbol(const char* modname, const char* symbol, int arg_count) {
    HookConf* cfg = (HookConf*)malloc(sizeof(HookConf));
    cfg->argc = (arg_count < 0 ? 0 : arg_count);
    cfg->target = nullptr;


    GumXHook hk{}; GError* err = NULL;
    GumInvocationListener* l = gumx_hook_symbol(modname, symbol,
                                                (GumXOnEnter)on_enter_bridge, (GumXOnLeave)on_leave_nop,
                                                cfg, (GDestroyNotify)free, &hk, &err);
    if (err != NULL || l == NULL) {
        if (err){ GUMX_LOGE("gumx_hook_symbol err: %s", err->message); g_clear_error(&err); }
        free(cfg);
        return -1;
    }
    cfg->target = hk.target;
    GUMX_LOGI("hooked %s!%s argc=%d @%p", modname?modname:"*", symbol, cfg->argc, hk.target);
    return 0;
}

// 钩取 RVA（相对模块基址）
extern "C"
int gqb_hook_rva(const char* modname, uint64_t rva, int arg_count) {
    HookConf* cfg = (HookConf*)malloc(sizeof(HookConf));
    cfg->argc = (arg_count < 0 ? 0 : arg_count);
    cfg->target = nullptr;

    GumXHook hk{}; GError* err = NULL;
    GumInvocationListener* l = gumx_hook_rva(modname, (GumAddress)rva,
                                             (GumXOnEnter)on_enter_bridge, (GumXOnLeave)on_leave_nop,
                                             cfg, (GDestroyNotify)free, &hk, &err);
    if (err != NULL || l == NULL) {
        if (err){ GUMX_LOGE("gumx_hook_rva err: %s", err->message); g_clear_error(&err); }
        free(cfg);
        return -1;
    }
    cfg->target = hk.target;
    GUMX_LOGI("hooked %s+0x%" PRIx64 " argc=%d @%p", modname?modname:"(null)", rva, cfg->argc, hk.target);
    return 0;
}

// 钩取偏移（=RVA）
extern "C"
int gqb_hook_offset(const char* modname, uint64_t offset, int arg_count) {
    // 这里 offset 即模块内 RVA，直接复用 gqb_hook_rva
    return gqb_hook_rva(modname, offset, arg_count);   // ★ 修正：不再递归自身
}

extern "C"
void gqb_shutdown(void) {
    fastsink_flush();
    fastsink_close();
    if (g_sym) { sosym_destroy(g_sym); g_sym = nullptr; }
    gumx_shutdown();
}
