#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void gqb_init_all(const char* log_path, const char* const* hook_so_names, int hook_so_count);
// 1) 初始化日志落盘（建议在 JNI_OnLoad 调一次）
void gqb_init_sink(const char* path);

// 2) 基于 gumx 安装 Hook（按符号名或 RVA）
//    arg_count : 0~6（从 x0..x5 取），JNI 典型函数传 2 即可。
int  gqb_hook_symbol(const char* modname, const char* symbol, int arg_count);
int  gqb_hook_rva(const char* modname, uint64_t rva, int arg_count);
int  gqb_hook_offset(const char* modname, uint64_t offset, int arg_count);

// 3) 可选：关闭（进程退出时自动清理也可）
void gqb_shutdown(void);

#ifdef __cplusplus
}
#endif
