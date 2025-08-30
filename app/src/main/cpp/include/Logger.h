//
// Created by Administrator on 2025/8/16.
//

#ifndef PROOT_LOGGER_H
#define PROOT_LOGGER_H

// ---- 配置开关（可在编译命令或包含前自定义） ----
// 默认日志 TAG
#ifndef PLOG_TAG
#define PLOG_TAG "SmallTrace"
#endif

#define PLOG_LEVEL_VERBOSE 2

// 编译期最小日志级别：更高的级别会被编译掉
// NDEBUG 时默认 INFO，否则 VERBOSE
#ifndef PLOG_COMPILE_LEVEL
#ifdef NDEBUG
#define PLOG_COMPILE_LEVEL 4  /* INFO */
#else
#define PLOG_COMPILE_LEVEL 2  /* VERBOSE */
#endif
#endif

// ---- 头文件与级别常量 ----
#include <stdio.h>
#include <string.h>

#if defined(__ANDROID__)
#include <android/log.h>
  enum {
    PLOG_VERBOSE = ANDROID_LOG_VERBOSE, // 2
    PLOG_DEBUG   = ANDROID_LOG_DEBUG,   // 3
    PLOG_INFO    = ANDROID_LOG_INFO,    // 4
    PLOG_WARN    = ANDROID_LOG_WARN,    // 5
    PLOG_ERROR   = ANDROID_LOG_ERROR,   // 6
    PLOG_FATAL   = ANDROID_LOG_FATAL,   // 7
    PLOG_SILENT  = ANDROID_LOG_SILENT   // 8
  };
#else
// 非 Android 环境的回退（保持与 ANDROID_LOG_* 数值一致）
enum {
    PLOG_VERBOSE = 2,
    PLOG_DEBUG   = 3,
    PLOG_INFO    = 4,
    PLOG_WARN    = 5,
    PLOG_ERROR   = 6,
    PLOG_FATAL   = 7,
    PLOG_SILENT  = 8
};
#endif

// 取文件名（优先用编译器提供的 __FILE_NAME__）
#if defined(__FILE_NAME__)
#define PLOG_FILE (__FILE_NAME__)
#elif defined(__GNUC__) || defined(__clang__)
#define PLOG_FILE (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#else
#define PLOG_FILE (__FILE__)
#endif

// ---- 实际打印宏（内部） ----
#if defined(__ANDROID__)
#define PLOG__PRINT(_prio, _fmt, ...) \
    do { \
      if ((_prio) >= PLOG_COMPILE_LEVEL) { \
        __android_log_print((_prio), PLOG_TAG, "%s:%d | " _fmt, PLOG_FILE, __LINE__, ##__VA_ARGS__); \
      } \
    } while (0)
#else
// 回退：打印到 stderr，并附上级别字符串
static inline const char* plog__prio_str(int p) {
    switch (p) {
        case 2: return "VERBOSE";
        case 3: return "DEBUG";
        case 4: return "INFO";
        case 5: return "WARN";
        case 6: return "ERROR";
        case 7: return "FATAL";
        default: return "LOG";
    }
}
#define PLOG__PRINT(_prio, _fmt, ...) \
    do { \
      if ((_prio) >= PLOG_COMPILE_LEVEL) { \
        fprintf(stderr, "[%s][%s] %s:%d | " _fmt "\n", PLOG_TAG, plog__prio_str((_prio)), PLOG_FILE, __LINE__, ##__VA_ARGS__); \
      } \
    } while (0)
#endif

// ---- 对外宏 ----
#define LOGV(_fmt, ...) PLOG__PRINT(PLOG_VERBOSE, _fmt, ##__VA_ARGS__)
#define LOGD(_fmt, ...) PLOG__PRINT(PLOG_DEBUG,   _fmt, ##__VA_ARGS__)
#define LOGI(_fmt, ...) PLOG__PRINT(PLOG_INFO,    _fmt, ##__VA_ARGS__)
#define LOGW(_fmt, ...) PLOG__PRINT(PLOG_WARN,    _fmt, ##__VA_ARGS__)
#define LOGE(_fmt, ...) PLOG__PRINT(PLOG_ERROR,   _fmt, ##__VA_ARGS__)
#define LOGF(_fmt, ...) PLOG__PRINT(PLOG_FATAL,   _fmt, ##__VA_ARGS__)

// ---- 便捷：十六进制 dump（小工具，可选） ----
static inline void LOG_HEXDUMP(const void* data, size_t len) {
#if (PLOG_VERBOSE >= PLOG_COMPILE_LEVEL) || (PLOG_DEBUG >= PLOG_COMPILE_LEVEL)
    const unsigned char* p = (const unsigned char*)data;
  char line[80];
  for (size_t i = 0; i < len; i += 16) {
    int n = snprintf(line, sizeof(line), "%08zx  ", i);
    for (size_t j = 0; j < 16; ++j) {
      if (i + j < len) n += snprintf(line + n, sizeof(line) - n, "%02x ", p[i + j]);
      else             n += snprintf(line + n, sizeof(line) - n, "   ");
    }
    n += snprintf(line + n, sizeof(line) - n, " ");
    for (size_t j = 0; j < 16 && i + j < len; ++j) {
      unsigned char c = p[i + j];
      line[n++] = (c >= 32 && c < 127) ? c : '.';
      if (n >= (int)sizeof(line) - 2) break;
    }
    line[n] = '\0';
    PLOG__PRINT(PLOG_DEBUG, "%s", line);
  }
#else
    (void)data; (void)len;
#endif
}

#endif // PROOT_LOGGER_H
