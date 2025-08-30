

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 句柄类型（不透明） */
typedef struct sosym_handle sosym_handle;

/* 创建/销毁 */
sosym_handle* sosym_create(void);
void          sosym_destroy(sosym_handle* h);

/* 预载：按 so 名称（如 "libfoo.so" / "foo" / "libfoo" 均可）
 * 仅对“当前已加载”的模块建立索引；未加载的会跳过。
 * 返回成功预载的数量（>=0）。*/
int sosym_preload_by_names(sosym_handle* h, const char* const* names, int count);

/* 预载：按绝对路径（/system/.../libxxx.so 或 /data/.../libxxx.so）
 * 同样仅索引“当前已加载”的模块；未加载会跳过。
 * 返回成功预载的数量（>=0）。*/
int sosym_preload_by_paths(sosym_handle* h, const char* const* paths, int count);

/* 只查缓存（严格模式）：
 * 传入任意 PC/内存地址，若属于已预载的某个 so 的函数区间，则返回去修饰后的函数名指针。
 * - out_so_path 可选：返回 so 真实路径的只读指针（TLS，有效期到当前线程下次调用）。
 * - out_func_rva  可选：函数起始 RVA（相对模块基址的虚拟地址偏移）。
 * - out_func_size 可选：函数大小；未知则为 0。
 * 查不到返回 NULL，不做任何解析/扫描。*/
const char* sosym_resolve_fast(sosym_handle* h,
                               uintptr_t addr,
                               const char** out_so_path,
                               uint64_t* out_func_rva,
                               uint64_t* out_func_size);

/* 与上相同，但把字符串拷贝到调用者提供的缓冲区，避免 TLS 生命周期问题。
 * 返回 1=命中；0=未命中。 */
int sosym_resolve_fast_buf(sosym_handle* h,
                           uintptr_t addr,
                           char* func_name_buf, size_t func_name_bufsz,
                           char* so_path_buf,  size_t so_path_bufsz,
                           uint64_t* out_func_rva,
                           uint64_t* out_func_size);

/* 统计信息：当前缓存中 so 数量与累计函数条目数 */
void sosym_stats(sosym_handle* h, size_t* out_so_count, size_t* out_func_total);

#ifdef __cplusplus
} /* extern "C" */
#endif