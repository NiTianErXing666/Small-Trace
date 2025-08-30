#include <jni.h>
#include <unistd.h>
#include "gum_qbdi_bridge.h"
#include "Logger.h"
//
// Created by Administrator on 2025/8/29.
//
extern int get_process_name(pid_t pid, char *name, size_t size);
//int get_process_name(pid_t pid, char *name, size_t size) {
//    char path[64];
//    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
//    FILE *fp = fopen(path, "r");
//    if (!fp) return -1;
//    if (!fgets(name, size, fp)) {
//        fclose(fp);
//        return -1;
//    }
//    fclose(fp);
//    return strlen(name);
//}

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



JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1hook_1trace(JNIEnv *env, jobject thiz) {
    // TODO: implement test_hook_trace()
    char name[128] = "unknown";
    if (get_process_name(getpid(), name, sizeof(name)) <= 0) {
        // 兜底：保持默认
        LOGE("get_process_name() failed");
        return;
    }
    char buf[256] ={0};
    sprintf(buf, "/data/data/%s/qbdi_trace.log", name);
//    gqb_init_sink(buf);

    static const char* kHooks[] = { "libqdbi.so", "libart.so", "libc.so","libnativelib.so" };
    gqb_init_all(buf, kHooks, (int)(sizeof(kHooks)/sizeof(kHooks[0])));


    gqb_hook_symbol("libnativelib.so", "Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi", /*argc*/2);

    LOGD("test_hook_trace() 完成！");
}

JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1hook_1trace_1test(JNIEnv *env, jobject thiz) {
    // TODO: implement test_hook_trace_test()
    char buf[32];
    size_t n = qdbi_decrypt_demo(buf, sizeof(buf));
    LOGI("decrypt => \"%s\" (len=%zu)", buf, n);
}