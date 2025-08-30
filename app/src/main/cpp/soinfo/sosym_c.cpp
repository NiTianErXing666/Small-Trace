#ifndef SOSYM_C_H
#define SOSYM_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄 */
typedef struct sosym_handle sosym_handle;

/* 创建/销毁 */
sosym_handle* sosym_create(void);
void          sosym_destroy(sosym_handle* h);

/* 预载：按 so 名称（如 "libqdbi.so" / "qdbi" / "libqdbi"）
 * 仅处理“当前已加载”的模块；未加载的跳过。
 * 返回新增进入缓存的 so 数量。*/
int sosym_preload_by_names(sosym_handle* h, const char* const* names, int count);

/* 预载：按路径（/system/... 或 /data/...）
 * 仍只处理“当前已加载”的模块；返回新增 so 数量。*/
int sosym_preload_by_paths(sosym_handle* h, const char* const* paths, int count);

/* 仅查询缓存（严格模式），不做任何解析/扫描：
 * 命中返回函数名（demangle 后，TLS 字符串）；未命中返回 NULL。
 * 可选输出：so真实路径（TLS 字符串）、函数起始RVA、函数大小(未知=0) */
const char* sosym_resolve_fast(sosym_handle* h,
                               uintptr_t addr,
                               const char** out_so_path,
                               uint64_t* out_func_rva,
                               uint64_t* out_func_size);

/* 与上类似，但把结果拷入调用者缓冲区；返回 1=命中，0=未命中 */
int sosym_resolve_fast_buf(sosym_handle* h,
                           uintptr_t addr,
                           char* func_name_buf, size_t func_name_bufsz,
                           char* so_path_buf,  size_t so_path_bufsz,
                           uint64_t* out_func_rva,
                           uint64_t* out_func_size);

/* 统计：当前缓存 so 数量与函数条目数 */
void sosym_stats(sosym_handle* h, size_t* out_so_count, size_t* out_func_total);

#ifdef __cplusplus
} /* extern "C" */
#endif


/* =====================  实  现  区  =====================
 * 仅在 **一个** C++ 源文件里：
 *   #define SOSYM_C_IMPLEMENTATION
 *   #include "sosym_c.h"
 * 即可把实现编进工程（stb-style）
 */
#define SOSYM_C_IMPLEMENTATION
#ifdef SOSYM_C_IMPLEMENTATION

#ifndef __cplusplus
#error "Define SOSYM_C_IMPLEMENTATION only in a C++ translation unit."
#endif

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <mutex>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <cxxabi.h>

namespace _sosym_impl {

static constexpr size_t MAX_DEMANGLE = 512;

static inline const char* demangle(const char* name, char out[MAX_DEMANGLE]) {
    if (!name || !*name) return nullptr;
    int status = 0; size_t len = 0;
    char* p = abi::__cxa_demangle(name, nullptr, &len, &status);
    if (status == 0 && p) { strncpy(out, p, MAX_DEMANGLE-1); out[MAX_DEMANGLE-1]='\0'; std::free(p); return out; }
    strncpy(out, name, MAX_DEMANGLE-1); out[MAX_DEMANGLE-1]='\0'; return out;
}

struct MMapFile {
    int fd{-1}; size_t size{0}; void* map{MAP_FAILED};
    bool open(const char* path){
        fd = ::open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st{};
        if (fstat(fd, &st) != 0 || st.st_size <= 0) { ::close(fd); fd=-1; return false; }
        size = (size_t)st.st_size;
        map = ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { ::close(fd); fd=-1; return false; }
        return true;
    }
    ~MMapFile(){ if (map!=MAP_FAILED) ::munmap(map, size); if (fd>=0) ::close(fd); }
};

/* 名称匹配：支持 foo / foo.so / libfoo / libfoo.so，且兼容 libc++.so.1 */
static inline bool name_matches(const char* file_base, const char* query_raw) {
    if (!file_base || !*file_base || !query_raw || !*query_raw) return false;
    auto basename = [](const char* p)->std::string{ const char* b=strrchr(p,'/'); b=b?b+1:p; return std::string(b); };
    std::string q = basename(query_raw);
    std::vector<std::string> cand; cand.push_back(q);
    if (q.rfind(".so") == std::string::npos) {
        cand.push_back(q + std::string(".so"));
        cand.push_back(std::string("lib") + q);
        cand.push_back(std::string("lib") + q + ".so");
    }
    for (auto& c : cand) {
        if (strncmp(file_base, c.c_str(), c.size()) == 0) {
            char next = file_base[c.size()];
            if (next == '\0' || next == '.') return true;
        }
    }
    for (auto& c : cand) if (c == file_base) return true;
    return false;
}

/* 计算模块 [base,end)（PT_LOAD 汇总） */
static inline bool phdr_range(const dl_phdr_info* info, uintptr_t& base, uintptr_t& end) {
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t seg_lo = (uintptr_t)info->dlpi_addr + ph->p_vaddr;
        uintptr_t seg_hi = seg_lo + ph->p_memsz;
        if (seg_lo < lo) lo = seg_lo;
        if (seg_hi > hi) hi = seg_hi;
    }
    if (lo < hi) { base = lo; end = hi; return true; }
    return false;
}

/* 从内存的 PT_DYNAMIC 解析 .dynsym/.strtab（导出符号；适配 APK 内 mmap） */
struct Func { uint64_t start; uint64_t end; std::string name; }; // [start,end)
// 从内存的 PT_DYNAMIC 解析 .dynsym/.strtab（导出符号；适配 APK 内 mmap）
    static bool parseDynsymFromDl(const dl_phdr_info* info, std::vector<Func>& out) {
        // 1) 找 PT_DYNAMIC
        const ElfW(Phdr)* dynph = nullptr;
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dynph = &info->dlpi_phdr[i]; break;
            }
        }
        if (!dynph) return false;

        const uintptr_t base = (uintptr_t)info->dlpi_addr;     // <<<<<< 关键：load bias
        const ElfW(Dyn)* dyn = (const ElfW(Dyn)*)(base + dynph->p_vaddr);

        // 2) 拉取关键动态条目（全部 +base）
        const char*      strtab   = nullptr; size_t strsz = 0;
        const ElfW(Sym)* symtab   = nullptr; size_t syment = sizeof(ElfW(Sym));
        const uint32_t*  sysv_hash= nullptr;
        const uint32_t*  gnu_hash = nullptr;

        for (const ElfW(Dyn)* d = dyn; d && d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_STRTAB:   strtab    = (const char*)(base + d->d_un.d_ptr); break;
                case DT_STRSZ:    strsz     = (size_t)d->d_un.d_val;               break;
                case DT_SYMTAB:   symtab    = (const ElfW(Sym)*)(base + d->d_un.d_ptr); break;
                case DT_SYMENT:   syment    = (size_t)d->d_un.d_val;               break;
                case DT_HASH:     sysv_hash = (const uint32_t*)(base + d->d_un.d_ptr); break;
                case DT_GNU_HASH: gnu_hash  = (const uint32_t*)(base + d->d_un.d_ptr); break;
                default: break;
            }
        }
        if (!strtab || !symtab || syment != sizeof(ElfW(Sym))) return false;

        // 3) 估算符号个数（优先 SysV，其次 GNU）
        size_t nsyms = 0;
        if (sysv_hash) {
            // SysV hash: [nbucket, nchain, ...]
            nsyms = (size_t)sysv_hash[1];
        } else if (gnu_hash) {
            // GNU hash：header(4*u32) + bloom[sz]*ElfW(Addr) + buckets[nb] + chains[]
            const uint32_t nbuckets   = gnu_hash[0];
            const uint32_t symoffset  = gnu_hash[1];
            const uint32_t bloom_size = gnu_hash[2];
            // 指针算术尽量用字节指针，避免 32/64 差异
            const char* p = (const char*)(gnu_hash + 4);
            p += bloom_size * sizeof(ElfW(Addr));             // 跳过 bloom
            const uint32_t* buckets = (const uint32_t*)p;
            const uint32_t* chains  = buckets + nbuckets;

            uint32_t maxidx = symoffset;
            for (uint32_t b = 0; b < nbuckets; ++b) {
                uint32_t idx = buckets[b];
                if (idx == 0 || idx < symoffset) continue;
                // 沿链走到末尾（最低位 1）
                do {
                    uint32_t c = chains[idx - symoffset];
                    if (idx > maxidx) maxidx = idx;
                    if (c & 1) break;
                    ++idx;
                } while (true);
            }
            nsyms = (size_t)maxidx + 1;
        } else {
            return false;
        }

        // 保底：防止奇异值把你拖爆（过大时直接截断）
        const size_t NSYMS_HARD_CAP = 1u << 20; // 约 100 万
        if (nsyms > NSYMS_HARD_CAP) nsyms = NSYMS_HARD_CAP;

        // 4) 收集 STT_FUNC
        out.clear(); out.reserve(nsyms/3 + 8);
        for (size_t i = 0; i < nsyms; ++i) {
            const ElfW(Sym)& s = symtab[i];
            if (s.st_name >= strsz || s.st_name == 0 || s.st_value == 0) continue;
#if INTPTR_MAX == INT64_MAX
            unsigned type = ELF64_ST_TYPE(s.st_info);
#else
            unsigned type = ELF32_ST_TYPE(s.st_info);
#endif
            if (type != STT_FUNC) continue;

            const char* nm = strtab + s.st_name;
            if (!nm || !*nm) continue;

            Func f;
            f.start = (uint64_t)s.st_value;             // 注意：这里是 RVA（相对 module base）
            uint64_t sz = (uint64_t)s.st_size;
            f.end   = sz ? (f.start + sz) : 0;
            f.name  = nm;
            out.emplace_back(std::move(f));
        }
        if (out.empty()) return false;

        // 5) 排序 + 尺寸推导
        std::sort(out.begin(), out.end(), [](const Func& a, const Func& b){
            if (a.start != b.start) return a.start < b.start;
            bool ae = a.end != 0, be = b.end != 0; if (ae != be) return ae; return a.name < b.name;
        });
        out.erase(std::unique(out.begin(), out.end(), [](const Func& a, const Func& b){
            return a.start == b.start && a.name == b.name;
        }), out.end());
        for (size_t i = 0; i < out.size(); ++i) {
            if (out[i].end == 0) {
                uint64_t nextStart = (i+1 < out.size()) ? out[i+1].start : (out[i].start + 1);
                out[i].end = (nextStart > out[i].start) ? nextStart : (out[i].start + 1);
            }
        }
        return true;
    }

/* 文件解析（extractNativeLibs=true 可走，更全） */
static bool parseElfFunctions(const char* so_path, std::vector<Func>& out) {
    /* mmap ELF 再收集 .dynsym/.symtab 的 STT_FUNC */
    MMapFile mf; if (!mf.open(so_path)) return false;
    auto* eh = (const ElfW(Ehdr)*)mf.map;
    if (!(eh->e_ident[EI_MAG0]==ELFMAG0 && eh->e_ident[EI_MAG1]==ELFMAG1 &&
          eh->e_ident[EI_MAG2]==ELFMAG2 && eh->e_ident[EI_MAG3]==ELFMAG3)) return false;
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) return false;

    const uint8_t* base = (const uint8_t*)mf.map;
    const ElfW(Shdr)* shdrs = (const ElfW(Shdr)*)(base + eh->e_shoff);
    size_t shnum = eh->e_shnum;

    auto collect = [&](const ElfW(Shdr)* sym, const ElfW(Shdr)* str){
        const char* strtab = (const char*)base + str->sh_offset;
        size_t cnt = sym->sh_size / sym->sh_entsize;
        auto* syms = (const ElfW(Sym)*)(base + sym->sh_offset);
        for (size_t i=0;i<cnt;i++) {
            const ElfW(Sym)& s = syms[i];
#if INTPTR_MAX == INT64_MAX
            unsigned type = ELF64_ST_TYPE(s.st_info);
#else
            unsigned type = ELF32_ST_TYPE(s.st_info);
#endif
            if (type != STT_FUNC) continue;
            if (s.st_name == 0 || s.st_value == 0) continue;
            const char* nm = strtab + s.st_name; if (!nm || !*nm) continue;
            Func f; f.start = (uint64_t)s.st_value;
            uint64_t sz = (uint64_t)s.st_size;
            f.end = sz ? (f.start + sz) : 0;
            f.name = nm;
            out.emplace_back(std::move(f));
        }
    };

    const ElfW(Shdr) *dynsym=nullptr,*dynstr=nullptr,*symtab=nullptr,*strtab=nullptr;
    for (size_t i=0;i<shnum;i++){ if (shdrs[i].sh_type==SHT_DYNSYM) dynsym=&shdrs[i];
                                   if (shdrs[i].sh_type==SHT_SYMTAB) symtab=&shdrs[i]; }
    if (dynsym){ dynstr=&shdrs[dynsym->sh_link]; collect(dynsym,dynstr); }
    if (symtab){ strtab=&shdrs[symtab->sh_link]; collect(symtab,strtab); }

    if (out.empty()) return false;

    std::sort(out.begin(), out.end(), [](const Func& a, const Func& b){
        if (a.start != b.start) return a.start < b.start;
        bool ae = a.end != 0, be = b.end != 0; if (ae != be) return ae; return a.name < b.name;
    });
    out.erase(std::unique(out.begin(), out.end(), [](const Func& a, const Func& b){
        return a.start == b.start && a.name == b.name;
    }), out.end());
    for (size_t i=0;i<out.size();++i) {
        if (out[i].end == 0) {
            uint64_t nextStart = (i+1<out.size()) ? out[i+1].start : (out[i].start + 1);
            out[i].end = (nextStart > out[i].start) ? nextStart : (out[i].start + 1);
        }
    }
    return true;
}

/* 缓存条目 */
struct SoEntry {
    std::string path;        /* info->dlpi_name，可能是 base.apk!/lib/... */
    uintptr_t   base{0};
    uintptr_t   end{0};
    std::vector<Func> funcs; /* 按 start 升序 */
};

class Cache {
public:
    /* 预载（按名称）：遍历已加载模块，匹配名称 → 先内存解析，能 open 再文件补强 */
    void preloadByNames(const std::vector<std::string>& names) {
        std::unordered_set<std::string> seen;
        struct Ctx { Cache* self; const std::vector<std::string>* qs; } ctx{ this, &names };

        auto cb = [](struct dl_phdr_info* info, size_t, void* data)->int {
            auto* c = (Ctx*)data;
            if (!info->dlpi_name || !*info->dlpi_name) return 0;

            /* basename & APK 内部名 */
            const char* pname = info->dlpi_name;
            const char* baseA = strrchr(pname, '/'); baseA = baseA ? baseA + 1 : pname;
            const char* inside = nullptr;
            if (const char* excl = strchr(pname, '!')) {
                inside = strrchr(excl, '/'); inside = inside ? inside + 1 : excl + 1;
            }

            auto hit_name = [&](const std::string& q)->bool {
                return name_matches(baseA, q.c_str()) || (inside && name_matches(inside, q.c_str()));
            };
            bool wanted = false;
            for (auto& q : *c->qs) { if (hit_name(q)) { wanted = true; break; } }
            if (!wanted) return 0;

            uintptr_t base=0, end=0;
            if (!phdr_range(info, base, end)) return 0;

            /* 先内存导出符号（适配 extractNativeLibs=false） */
            std::vector<Func> funcs_dyn;
            bool ok_dyn = parseDynsymFromDl(info, funcs_dyn);

            /* 能以文件方式打开时，用文件符号覆盖（更全） */
            std::vector<Func> funcs_file;
            bool ok_file = parseElfFunctions(pname, funcs_file);

            if (!ok_dyn && !ok_file) return 0;

            SoEntry se;
            se.path = pname; se.base = base; se.end = end;
            se.funcs = ok_file ? std::move(funcs_file) : std::move(funcs_dyn);

            std::lock_guard<std::mutex> _{ c->self->mu_ };
            auto& entries = c->self->entries_;
            /* 用 path 去重（dlpi_name 在一次进程生命周期内稳定） */
            auto it = std::find_if(entries.begin(), entries.end(),
                                   [&](const SoEntry& x){ return x.path == se.path; });
            if (it == entries.end()) entries.push_back(std::move(se));
            else *it = std::move(se);
            return 0;
        };
        dl_iterate_phdr(cb, &ctx);

        std::lock_guard<std::mutex> _{ mu_ };
        std::sort(entries_.begin(), entries_.end(),
                  [](const SoEntry& a, const SoEntry& b){ return a.base < b.base; });
    }

    /* 预载（按路径）：若不能打开文件，则在已加载模块中找同名/basename 的条目做内存解析 */
    void preloadByPaths(const std::vector<std::string>& paths) {
        for (auto& path : paths) preloadOneByPath(path);
        std::lock_guard<std::mutex> _{ mu_ };
        std::sort(entries_.begin(), entries_.end(),
                  [](const SoEntry& a, const SoEntry& b){ return a.base < b.base; });
    }

    /* 仅查缓存 */
    const char* resolveFast(uintptr_t addr,
                            std::string* so_path,
                            uint64_t* func_rva,
                            uint64_t* func_size) const {
        std::lock_guard<std::mutex> _{ mu_ };
        size_t idx = findSoIndexByAddrNoLock(addr);
        if (idx == npos) return nullptr;
        const SoEntry& se = entries_[idx];
        if (so_path) *so_path = se.path;
        uint64_t rva = (uint64_t)addr - (uint64_t)se.base;

        int fidx = funcLowerBound(se.funcs, rva);
        if (fidx < 0) return nullptr;

        const Func& f = se.funcs[(size_t)fidx];
        if (func_rva)  *func_rva = f.start;
        if (func_size) *func_size = (f.end > f.start) ? (f.end - f.start) : 0;

        static thread_local char buf[MAX_DEMANGLE];
        return demangle(f.name.c_str(), buf);
    }

    void stats(size_t& so_count, size_t& func_total) const {
        std::lock_guard<std::mutex> _{ mu_ };
        so_count = entries_.size(); func_total = 0;
        for (auto& e : entries_) func_total += e.funcs.size();
    }

private:
    void preloadOneByPath(const std::string& path) {
        // 在已加载模块中先找匹配的 dlpi_name 或 basename（适配 base.apk!/lib/...）
        struct Ctx {
            const std::string* want;        // 目标路径字符串
            const char*        baseWant;    // want 的 basename（不含 '/')
            std::vector<Func>* out;         // 输出到的符号数组（内存解析）
            uintptr_t          base{0}, end{0};
            bool               ok{false};
        };

        std::vector<Func> funcs_dyn;
        const char* bw = strrchr(path.c_str(), '/');
        Ctx ctx{ &path, bw ? bw + 1 : path.c_str(), &funcs_dyn, 0, 0, false };

        auto cb = [](struct dl_phdr_info* info, size_t, void* data)->int {
            auto& c = *reinterpret_cast<Ctx*>(data);
            if (!info->dlpi_name || !*info->dlpi_name) return 0;

            const char* p = info->dlpi_name;
            const char* baseA = strrchr(p, '/'); baseA = baseA ? baseA + 1 : p;
            const char* inside = nullptr;
            if (const char* excl = strchr(p, '!')) {
                inside = strrchr(excl, '/'); inside = inside ? inside + 1 : excl + 1;
            }

            bool matched = (strcmp(p, c.want->c_str()) == 0) ||
                           name_matches(baseA, c.baseWant) ||
                           (inside && name_matches(inside, c.baseWant));
            if (!matched) return 0;

            if (!phdr_range(info, c.base, c.end)) return 0;
            if (!parseDynsymFromDl(info, *c.out)) return 0;
            c.ok = true;
            return 1; // 找到就提前结束
        };
        dl_iterate_phdr(cb, &ctx);

        std::vector<Func> funcs_file;
        bool ok_file = parseElfFunctions(path.c_str(), funcs_file);

        if (!ctx.ok && !ok_file) return;

        SoEntry se;
        se.path  = path;             // 用传入的 path 作为键
        se.base  = ctx.ok ? ctx.base : se.base;
        se.end   = ctx.ok ? ctx.end  : se.end;
        se.funcs = ok_file ? std::move(funcs_file) : std::move(funcs_dyn);

        std::lock_guard<std::mutex> _{ mu_ };
        auto it = std::find_if(entries_.begin(), entries_.end(),
                               [&](const SoEntry& x){ return x.path == se.path; });
        if (it == entries_.end()) entries_.push_back(std::move(se));
        else *it = std::move(se);
    }

    size_t findSoIndexByAddrNoLock(uintptr_t addr) const {
        size_t lo=0, hi=entries_.size();
        while (lo<hi) {
            size_t mid=(lo+hi)/2;
            if (entries_[mid].base <= addr) lo=mid+1; else hi=mid;
        }
        if (lo==0) return npos;
        size_t i=lo-1;
        if (addr < entries_[i].end) return i;
        return npos;
    }

    static int funcLowerBound(const std::vector<Func>& v, uint64_t rva) {
        size_t lo=0, hi=v.size();
        while (lo<hi) {
            size_t mid=(lo+hi)/2;
            if (v[mid].start <= rva) lo=mid+1; else hi=mid;
        }
        if (lo==0) return -1;
        size_t i=lo-1;
        if (rva >= v[i].start && rva < v[i].end) return (int)i;
        return -1;
    }

private:
    static constexpr size_t npos = (size_t)-1;
    mutable std::mutex mu_;
    std::vector<SoEntry> entries_;  /* 按 base 升序 */
};

} // namespace _sosym_impl


/* ----------------- C 包装 ----------------- */
struct sosym_handle { _sosym_impl::Cache cache; };

static inline const char* _sosym_tls_copy(const char* s) {
    static thread_local char buf[512];
    if (!s) return NULL;
    size_t n = strlen(s); if (n >= sizeof(buf)) n = sizeof(buf)-1;
    memcpy(buf, s, n); buf[n] = '\0'; return buf;
}
static inline const char* _sosym_tls_copy_path(const std::string& s) {
    static thread_local char buf[1024];
    size_t n = s.size(); if (n >= sizeof(buf)) n = sizeof(buf)-1;
    memcpy(buf, s.data(), n); buf[n] = '\0'; return buf;
}

extern "C" {

sosym_handle* sosym_create(void) { return new (std::nothrow) sosym_handle(); }
void          sosym_destroy(sosym_handle* h) { delete h; }

int sosym_preload_by_names(sosym_handle* h, const char* const* names, int count) {
    if (!h || !names || count <= 0) return 0;
    std::vector<std::string> v; v.reserve((size_t)count);
    for (int i=0;i<count;i++) if (names[i] && names[i][0]) v.emplace_back(names[i]);
    size_t so0=0, fn0=0; h->cache.stats(so0, fn0);
    h->cache.preloadByNames(v);
    size_t so1=0, fn1=0; h->cache.stats(so1, fn1);
    return (int)(so1 - so0);
}

int sosym_preload_by_paths(sosym_handle* h, const char* const* paths, int count) {
    if (!h || !paths || count <= 0) return 0;
    std::vector<std::string> v; v.reserve((size_t)count);
    for (int i=0;i<count;i++) if (paths[i] && paths[i][0]) v.emplace_back(paths[i]);
    size_t so0=0, fn0=0; h->cache.stats(so0, fn0);
    h->cache.preloadByPaths(v);
    size_t so1=0, fn1=0; h->cache.stats(so1, fn1);
    return (int)(so1 - so0);
}

const char* sosym_resolve_fast(sosym_handle* h,
                               uintptr_t addr,
                               const char** out_so_path,
                               uint64_t* out_func_rva,
                               uint64_t* out_func_size) {
    if (!h) return NULL;
    std::string path;
    const char* dem = h->cache.resolveFast(addr, &path, out_func_rva, out_func_size);
    if (!dem) return NULL;
    if (out_so_path) *out_so_path = _sosym_tls_copy_path(path);
    return _sosym_tls_copy(dem);
}

int sosym_resolve_fast_buf(sosym_handle* h,
                           uintptr_t addr,
                           char* func_name_buf, size_t func_name_bufsz,
                           char* so_path_buf,  size_t so_path_bufsz,
                           uint64_t* out_func_rva,
                           uint64_t* out_func_size) {
    if (!h) return 0;
    std::string path;
    const char* dem = h->cache.resolveFast(addr, &path, out_func_rva, out_func_size);
    if (!dem) return 0;
    if (func_name_buf && func_name_bufsz) {
        size_t n = strlen(dem); if (n >= func_name_bufsz) n = func_name_bufsz - 1;
        memcpy(func_name_buf, dem, n); func_name_buf[n] = '\0';
    }
    if (so_path_buf && so_path_bufsz) {
        size_t n = path.size(); if (n >= so_path_bufsz) n = so_path_bufsz - 1;
        memcpy(so_path_buf, path.data(), n); so_path_buf[n] = '\0';
    }
    return 1;
}

void sosym_stats(sosym_handle* h, size_t* out_so_count, size_t* out_func_total) {
    if (!h) { if(out_so_count)*out_so_count=0; if(out_func_total)*out_func_total=0; return; }
    size_t so=0, fn=0; h->cache.stats(so, fn);
    if (out_so_count)   *out_so_count   = so;
    if (out_func_total) *out_func_total = fn;
}

} /* extern "C" */

#endif /* SOSYM_C_IMPLEMENTATION */
#endif /* SOSYM_C_H */
