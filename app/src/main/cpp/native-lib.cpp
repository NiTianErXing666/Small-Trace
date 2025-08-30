#include <jni.h>
#include <android/log.h>
#include <cinttypes>
#include <vector>
#include <string>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include "QBDI.h"
//#define FASTSINK_IMPLEMENTATION
//#include "fastsink.h"


#define LOG_TAG "QBDITrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 目标明文: "hello qdbi!!!!" (14字节)
// 这里的密文是: plain[i] ^ (0x5A ^ i)
static const uint8_t kCipher[14] = {
        0x32,0x3E,0x34,0x35,0x31,0x7F,0x2D,0x39,0x30,0x3A,0x71,0x70,0x77,0x76
};
static const uint8_t kKey = 0x5A;

__attribute__((noinline))
size_t qdbi_decrypt_demo(char* out, size_t out_sz) {
    if (!out || out_sz < 15) return 0;
    // 逐字节解密：plain[i] = cipher[i] ^ (kKey ^ i)
    for (size_t i = 0; i < 14; i++) {
        uint8_t m = (uint8_t)(kKey ^ (uint8_t)i);
        out[i] = (char)(kCipher[i] ^ m);
    }
    out[14] = '\0';
    return 14;
}


// 初始化（建议在 JNI_OnLoad 或你的 init 里调用一次）
void init_trace_file() {
    // 传入 App 内部可写路径（示例）：
    // /data/data/<package>/files/qbdi_trace.log
//    fastsink_open("/data/user/0/io.calvin.qdbi/qbdi_trace.log", /*truncate=*/1);
//    fastsink_enable_timestamp(1);
//    fastsink_set_prefix("TRACE ");
}

/* ===== 示例目标，可替换为你想观测的函数地址 ===== */
extern "C" JNIEXPORT jstring JNICALL
Java_io_calvin_qdbi_MainActivity_stringFromJNI(JNIEnv* env, jobject) {
    char buf[32];
    size_t n = qdbi_decrypt_demo(buf, sizeof(buf));
    LOGI("decrypt => \"%s\" (len=%zu)", buf, n);
    return env->NewStringUTF(buf);
}

// 1) 新增：清顶字节
static inline uint64_t untag_addr(uint64_t a) {
#if defined(__aarch64__)
    return a & 0x00FFFFFFFFFFFFFFull; // 清掉 top-byte（TBI/MTE tag）
#else
    return a;
#endif
}
/* ===== /proc/self/mem 读取 + hexdump（高亮命中行 *） ===== */
static inline int selfmem() {
    static int fd = -2;
    if (fd == -2) {
        fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        if (fd < 0) { LOGE("open /proc/self/mem failed: %d", errno); fd = -1; }
    }
    return fd;
}
static inline size_t safe_read(uint64_t addr, void* buf, size_t len) {
    uint64_t ua = untag_addr(addr);
    int fd = selfmem();
    if (fd >= 0) {
        ssize_t n = pread(fd, buf, len, (off_t)ua);
        return (n > 0) ? (size_t)n : 0;
    } else {
        long ps = sysconf(_SC_PAGESIZE);
        uintptr_t a = (uintptr_t)ua;
        uintptr_t end = (a & ~(uintptr_t)(ps - 1)) + (uintptr_t)ps;
        size_t m = (a + len > end) ? (size_t)(end - a) : len;
        if (!m) return 0;
        memcpy(buf, reinterpret_cast<const void*>(a), m);
        return m;
    }
}
static inline void hexdump_window(uint64_t center, size_t window = 0x80) {
    uint64_t c = untag_addr(center);
    uint64_t start = (c & ~0xFULL) - (window/2);
    std::vector<uint8_t> buf(window);
    size_t got = safe_read(start, buf.data(), buf.size());
    if (got == 0) return;
    auto line = [](uint64_t addr, const uint8_t* p, size_t n, bool mark){
        static const char* H="0123456789ABCDEF";
        char hex[16*3 + 1]; size_t hp=0;
        for(size_t j=0;j<16;j++){
            if(j<n){ uint8_t b=p[j]; hex[hp++]=H[b>>4]; hex[hp++]=H[b&0xF]; }
            else   { hex[hp++]=' ';  hex[hp++]=' '; }
            hex[hp++]=' ';
        }
        hex[hp?hp-1:0]='\0';
        char asc[17]; for(size_t j=0;j<16;j++) asc[j]=(j<n && p[j]>=0x20 && p[j]<=0x7E)?(char)p[j]:' '; asc[16]='\0';
//        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%c%016" PRIx64 "  %s |%s|", mark?'*':' ', addr, hex, asc);
//        fastsink_writefln("%c%016" PRIx64 "  %s |%s|", mark?'*':' ', addr, hex, asc);
    };
    for (uint64_t a=start; a<start+got; a+=16){
        size_t n = ((start+got - a) < 16) ? (size_t)(start+got - a) : 16;
        bool mark = (center >= a && center < a+16);
        line(a, &buf[(size_t)(a-start)], n, mark);
    }
//    fastsink_flush();
}

/* ===== 老版 GPRState 读取：x0..x28, x29, lr ===== */
static inline uint64_t getX(const QBDI::GPRState* g, int idx){
    switch(idx){
        case  0:return g->x0;  case  1:return g->x1;  case  2:return g->x2;  case  3:return g->x3;
        case  4:return g->x4;  case  5:return g->x5;  case  6:return g->x6;  case  7:return g->x7;
        case  8:return g->x8;  case  9:return g->x9;  case 10:return g->x10; case 11:return g->x11;
        case 12:return g->x12; case 13:return g->x13; case 14:return g->x14; case 15:return g->x15;
        case 16:return g->x16; case 17:return g->x17; case 18:return g->x18; case 19:return g->x19;
        case 20:return g->x20; case 21:return g->x21; case 22:return g->x22; case 23:return g->x23;
        case 24:return g->x24; case 25:return g->x25; case 26:return g->x26; case 27:return g->x27;
        case 28:return g->x28; case 29:return g->x29; case 30:return g->lr;
        default:return 0;
    }
}
static inline const char* regName(int i){
    static const char* N[31]={"X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15","X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","X29","X30"};
    return (i>=0&&i<31)?N[i]:"X?";
}

/* ===== 追踪上下文 ===== */
struct TraceCtx {
    QBDI::rword fn = 0;
    int depth = 0;
    uint64_t preX[31]{};
    uint64_t iaVA = 0, iaRVA = 0;
    char     iaText[160]{};
};

/* ===== 入口哨兵：进入目标 ===== */
static QBDI::VMAction onEnter(QBDI::VM*, QBDI::GPRState*, QBDI::FPRState*, void* u){
    auto* ctx = (TraceCtx*)u;
    ctx->depth = 1;
//    fastsink_writefln("====== ENTER 0x%" PRIx64 " (global) ======", (uint64_t)ctx->fn);
    return QBDI::VMAction::CONTINUE;
}

/* ===== PRE：记录地址/文本/GPR快照 + 维护深度 ===== */
static QBDI::VMAction onPre(QBDI::VM* vm, QBDI::GPRState* g, QBDI::FPRState*, void* u){
    auto* ctx = (TraceCtx*)u;
    if (ctx->depth <= 0) return QBDI::VMAction::CONTINUE;

    const QBDI::InstAnalysis* ia = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY);
    if (!ia) return QBDI::VMAction::CONTINUE;

    ctx->iaVA = ia->address;
    // RVA：用 dladdr() 的 dli_fbase
    Dl_info dli{}; ctx->iaRVA = 0;
    if (dladdr((void*)ia->address, &dli) && dli.dli_fbase) {
        ctx->iaRVA = ia->address - (uintptr_t)dli.dli_fbase;
    }
    strncpy(ctx->iaText, ia->disassembly ? ia->disassembly : "", sizeof(ctx->iaText)-1);

    for (int i=0;i<31;i++) ctx->preX[i] = getX(g, i);

    if (ia->isCall)   ctx->depth++;
    if (ia->isReturn) { if (ctx->depth>0) ctx->depth--; if (ctx->depth==0) LOGI("======  LEAVE 0x%" PRIx64 " ======", (uint64_t)ctx->fn); }
    return QBDI::VMAction::CONTINUE;
}

/* ===== POST：打印指令 + 寄存器变化 + 内存访问 ===== */
static QBDI::VMAction onPost(QBDI::VM* vm, QBDI::GPRState* g, QBDI::FPRState*, void* u){
    auto* ctx = (TraceCtx*)u;
    if (ctx->depth < 0) return QBDI::VMAction::CONTINUE;

    // 哪个寄存器变了（取第一个）
    int changed = -1; uint64_t preV=0, postV=0;
    for (int i=0;i<31;i++){ uint64_t now = getX(g,i); if (now != ctx->preX[i]) { changed=i; preV=ctx->preX[i]; postV=now; break; } }

    // br/blr 寄存器展示
    int brIdx=-1;
    if (strncmp(ctx->iaText, "br ", 3)==0 || strncmp(ctx->iaText, "blr ", 4)==0){
        const char* p = strchr(ctx->iaText, 'x'); if (!p) p = strchr(ctx->iaText, 'X');
        if (p && isdigit((unsigned char)p[1])) { int n=atoi(p+1); if (n>=0&&n<=30) brIdx=n; }
    }

    if (changed >= 0) {
//        fastsink_writefln("0x%016" PRIx64 "\t0x%llx\t\t%s\t;%s=0x%llx -> 0x%llx",
//             (uint64_t)ctx->iaVA, (unsigned long long)ctx->iaRVA, ctx->iaText,
//             regName(changed), (unsigned long long)preV, (unsigned long long)postV);
    } else if (brIdx >= 0) {
        uint64_t v = getX(g, brIdx);
//        fastsink_writefln("0x%016" PRIx64 "\t0x%llx\t\t%s\t;%s=0x%llx",
//             (uint64_t)ctx->iaVA, (unsigned long long)ctx->iaRVA, ctx->iaText,
//             regName(brIdx), (unsigned long long)v);
    } else {
//        fastsink_writefln("0x%016" PRIx64 "\t0x%llx\t\t%s",
//             (uint64_t)ctx->iaVA, (unsigned long long)ctx->iaRVA, ctx->iaText);
    }

    // 内存访问（老版本字段名可能是 size）
    auto accs = vm->getInstMemoryAccess();
    for (const auto& ma : accs) {
        uint64_t addr_raw = (uint64_t)ma.accessAddress;
        uint64_t addr_rd  = untag_addr(addr_raw);

        size_t   sz  = (ma.size ? ma.size : (ma.size ? ma.size : 8));
        uint8_t  vbuf[8]{};
        size_t   want = (sz <= 8 ? sz : 8);
        size_t   got  = safe_read(addr_rd, vbuf, want);

        char valhex[2*8+1] = {0};
        for (size_t i=0;i<got;i++) sprintf(valhex + i*2, "%02x", vbuf[i]);

//        fastsink_writefln("memory %s at 0x%" PRIx64 ", instruction address = 0x%" PRIx64
                     ", data size = %zu, data value = %s",
//             (ma.type & QBDI::MEMORY_WRITE) ? "write" : "read",
//             addr_raw, (uint64_t)ctx->iaVA, (size_t)sz, valhex);

        hexdump_window(addr_raw); // hexdump_window 内部会自行 untag 再读
    }
    return QBDI::VMAction::CONTINUE;
}

/* ===== JNI 入口：保持你方法名，开启“全局 trace 到 ret” ===== */
extern "C" JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1qdbi(JNIEnv* env, jobject thiz) {
    //初始化 日志
    init_trace_file();

    QBDI::VM vm;
    TraceCtx ctx{};

    // 目标函数：你也可以换成任何需要观测的地址
    ctx.fn = reinterpret_cast<QBDI::rword>(&Java_io_calvin_qdbi_MainActivity_stringFromJNI);

    // 虚拟栈
    QBDI::GPRState* g = vm.getGPRState();
    uint8_t* fakestack = nullptr;
    if (!QBDI::allocateVirtualStack(g, 1u<<20, &fakestack)) {
//        fastsink_writefln("allocateVirtualStack failed");
        return;
    }

    // ★ 全局插桩（跨库、跨模块）：日志会很多，先在测试机跑
    vm.instrumentAllExecutableMaps();

    // 入口哨兵 + PRE/POST
    if (vm.addCodeAddrCB(ctx.fn, QBDI::InstPosition::PREINST, onEnter, &ctx) == QBDI::INVALID_EVENTID ||
        vm.addCodeCB(QBDI::InstPosition::PREINST,  onPre,  &ctx) == QBDI::INVALID_EVENTID ||
        !vm.recordMemoryAccess(QBDI::MEMORY_READ | QBDI::MEMORY_WRITE) ||
        vm.addCodeCB(QBDI::InstPosition::POSTINST, onPost, &ctx) == QBDI::INVALID_EVENTID) {
//        fastsink_writefln("register callbacks failed");
        QBDI::alignedFree(fakestack);
        return;
    }

    // 在 QBDI 下执行：一路 trace 到最外层 ret
    QBDI::rword ret = 0;
    bool ok = vm.call(&ret, ctx.fn, { (QBDI::rword)env, (QBDI::rword)thiz });
//    fastsink_writefln("vm.call ok=%d, ret=0x%" PRIx64, (int)ok, (uint64_t)ret);

    // 可选：校验 JNI 返回
    if (ok && ret) {
        jstring jret = reinterpret_cast<jstring>(ret);
        const char* s = env->GetStringUTFChars(jret, nullptr);
        if (s) { LOGI("ret=\"%s\"", s); env->ReleaseStringUTFChars(jret, s); }
        env->DeleteLocalRef(jret);
    }
//    fastsink_close();
    QBDI::alignedFree(fakestack);
}
