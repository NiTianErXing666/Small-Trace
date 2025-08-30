//
// Created by Administrator on 2025/8/29.
//
#include "gum_qbdi_bridge.h"
#include "Logger.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "core.h"
#include "gumx.h"
#include <jni.h>

int Calvin_Trace_symbol(char *soName,char *symbolName,int args);
int Calvin_Trace_offset(char *soName,unsigned long addr,int args);
int get_process_name(pid_t pid, char *name, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(name, size, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return strlen(name);
}

int Calvin_Trace_offset(char *soName,unsigned long addr,int args){
    char name[128] = "unknown";
    if (get_process_name(getpid(), name, sizeof(name)) <= 0) {
        // 兜底：保持默认
        LOGE("get_process_name() failed");
        return -1;
    }
    char buf[256] ={0};
    sprintf(buf, "/data/data/%s/qbdi_trace.log", name);

    char attach_so[128] = {0};
    sprintf(attach_so, "%s", soName);
    static const char* kHooks[3]={0};
    kHooks[0] = attach_so;
    kHooks[1] = (char*)"libc.so";
    kHooks[2] = (char*)"libart.so";
    gqb_init_all(buf, kHooks, (int)(sizeof(kHooks)/sizeof(kHooks[0])));

    gqb_hook_rva(attach_so, addr, /*argc*/args);

    LOGD("Calvin_Trace_offset() 完成！");
}

int Calvin_Trace_symbol(char *soName,char *symbolName,int args){
    char name[128] = "unknown";
    if (get_process_name(getpid(), name, sizeof(name)) <= 0) {
        // 兜底：保持默认
        LOGE("get_process_name() failed");
        return -1;
    }
    char buf[256] ={0};
    sprintf(buf, "/data/data/%s/qbdi_trace.log", name);

    char attach_so[128] = {0};
    sprintf(attach_so, "%s", soName);
    static const char* kHooks[3]={0};
    kHooks[0] = attach_so;
    kHooks[1] = (char*)"libc.so";
    kHooks[2] = (char*)"libart.so";
    gqb_init_all(buf, kHooks, (int)(sizeof(kHooks)/sizeof(kHooks[0])));

    gqb_hook_symbol(attach_so, symbolName, /*argc*/args);

    LOGD("Calvin_Trace_symbol() 完成！");
}

static void my_on_enter_bridge(GumInvocationContext* ic, gpointer user_data) {
    LOGD("my_on_enter_bridge()");

}
static void my_on_leave_nop(GumInvocationContext*, gpointer){
    LOGD("my_on_leave_nop()");
}
typedef struct { int argc; void* target; } HookConf;

JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1ceshi_1qdbi_1hook(JNIEnv *env, jobject thiz) {
    // TODO: implement test_ceshi_qdbi_hook()
    Calvin_Trace_symbol("libnativelib.so","Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi",2);
    LOGD("Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi() 完成！");
//    gumx_init();
//    HookConf* cfg = (HookConf*)malloc(sizeof(HookConf));
//    cfg->argc =0;
//    cfg->target = 0;
//
//
//    GumXHook hk; GError* err = NULL;
//    GumInvocationListener* l = gumx_hook_symbol("libnativelib.so", "Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi",
//                                                (GumXOnEnter)my_on_enter_bridge, (GumXOnLeave)my_on_leave_nop,
//                                                cfg, (GDestroyNotify)free, &hk, &err);
//    if (err != NULL || l == NULL) {
//        if (err){ GUMX_LOGE("gumx_hook_symbol err: %s", err->message); g_clear_error(&err); }
//        free(cfg);
//    }
//    cfg->target = hk.target;
//    GUMX_LOGI("hooked libnativelib Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi");
}