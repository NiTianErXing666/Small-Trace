#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_io_test_nativelib_NativeLib_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

// 判断 Base64 字符是否有效
inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

// Base64 解码函数
std::string base64_decode(const std::string &encoded) {
    const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int in_len = encoded.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded[in_] != '=') && is_base64(encoded[in_])) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            }
            char_array_3[0] = (char_array_4[0] << 2) | (char_array_4[1] >> 4);
            char_array_3[1] = (char_array_4[1] << 4) | (char_array_4[2] >> 2);
            char_array_3[2] = (char_array_4[2] << 6) | char_array_4[3];
            for (i = 0; (i < 3); i++) {
                ret += char_array_3[i];
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        for (int j = 0; j < 4; j++) {
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        }
        char_array_3[0] = (char_array_4[0] << 2) | (char_array_4[1] >> 4);
        char_array_3[1] = (char_array_4[1] << 4) | (char_array_4[2] >> 2);
        char_array_3[2] = (char_array_4[2] << 6) | char_array_4[3];
        for (int j = 0; (j < i - 1); j++) {
            ret += char_array_3[j];
        }
    }

    return ret;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_io_test_nativelib_NativeLib_test_1ceshi_1qdbi(
        JNIEnv *env, jclass thiz) {
    // TODO: implement test_ceshi_qdbi()
    // 假设你有一个 Base64 编码的字符串
//    std::string encoded_string = "aGVsbG8gdGhpcyBpcyB0ZXN0ICEhISE="; // "hello this is test!" 的 Base64 编码

    // 使用 base64_decode 函数解码
//    std::string decoded_string = base64_decode(encoded_string);

    // 返回解码后的字符串
    return env->NewStringUTF("ok");
}