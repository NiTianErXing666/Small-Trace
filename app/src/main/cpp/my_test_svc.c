//
// Created by Administrator on 2025/8/29.
//

#include "my_test_svc.h"
#include <jni.h>

#include "Logger.h"
#include "svclibc.h"

JNIEXPORT void JNICALL
Java_io_calvin_qdbi_MainActivity_test_1svc(JNIEnv *env, jobject thiz) {
    // TODO: implement test_svc()
    long fd = sv_openat(AT_FDCWD, "/proc/self/cmdline", /*O_RDONLY*/0, 0);
    if (fd >= 0) {
        char buf[128];
        long n = sv_read((int)fd, buf, sizeof(buf));
//        if (n > 0) sv_write(2, buf, (unsigned long)n); // 写到 stderr
        LOGD("read %ld bytes: %s", n, buf);
        sv_close((int)fd);
    }
}