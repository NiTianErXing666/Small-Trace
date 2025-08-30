#include <jni.h>
#define SOSYM_C_IMPLEMENTATION
#define SOSYM_C_IMPLEMENTATION
#include "sosym_c.h"
#include "Logger.h"
//
// Created by Administrator on 2025/8/29.
//

sosym_handle* h;

void init_resolver() {
    static const char* names[] = { "libart.so", "libc++_shared.so", "libc.so","libqdbi.so" };
    h = sosym_create();
    sosym_preload_by_names(h, names, 4);
    /* 保存全局 h … */
}

void test_fu_hao() {
}

JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1soinfo(JNIEnv *env, jobject thiz) {
    // TODO: implement test_soinfo()
    init_resolver();
    LOGD("初始化完成！");
    const char* so_path = NULL;
    uint64_t rva = 0, size = 0;
    const char* name = sosym_resolve_fast(h, (uintptr_t)&test_fu_hao, &so_path, &rva, &size);
    if (!name) {
        /* 未命中：可能不在预载库内或该 so 完全 strip */
        LOGD("未命中");
        return;
    }else{
        LOGD("命中：%s %s %p %x", name, so_path, (void*)rva, (void*)size);
    }
}