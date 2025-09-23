//
// Created by zWX1124406 on 2025/8/26.
//

#ifndef CPP_JNICALLBACK_H
#define CPP_JNICALLBACK_H

#ifdef __ANDROID__
#include <jni.h>
#include <string>

// 1. 定义我们所要保存的全局数据结构
struct GlobalCallBackContext {
    JavaVM* g_jvm = nullptr;          // 保存JavaVM指针
    jclass g_javaCallbackObj = nullptr; // 保存Java回调对象的全局引用
    jmethodID g_encryptMethodId = nullptr; // 保存回调方法ID
    jmethodID g_decryptMethodId = nullptr; // 保存回调方法ID
};

static GlobalCallBackContext g_ctx; // 全局实例

extern "C" {
std::string encryptByJava(std::string data);
std::string decryptByJava(std::string encryptedData);
}

#endif //__ANDROID__
#endif //CPP_JNICALLBACK_H
