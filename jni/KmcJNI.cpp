//
// Created by zWX1124406 on 2025/8/18.
//
#include "IKmcService.h"
#include "KmcContextManager.h"
#include "KmcLogInterface.h"
#include "JniCallBack.h"
#ifdef ENABLE_COMPILE_TEE
#include "kmc-tee.h"
#endif
#include <string>
#include <cstring>
#include <jni.h>

extern "C" {

#ifdef __ANDROID__
// 当本地库被加载时（通常在JNI_OnLoad），保存JavaVM*
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_ctx.g_jvm = vm; // 缓存JavaVM指针，它是全局有效的
    return JNI_VERSION_1_6;
}

// 一个辅助函数，用于为当前线程获取JNIEnv*
JNIEnv* getJniEnv() {
    JNIEnv* env = nullptr;
    // 检查当前线程是否已经附加到VM
    jint status = g_ctx.g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) { // 如果尚未附加
        // 将当前线程附加到VM，获取JNIEnv
        status = g_ctx.g_jvm->AttachCurrentThread(&env, nullptr);
        if (status != JNI_OK) {
            KMC::kmclog_e(LOG_TAG, "Failed to attach thread");
            return nullptr;
        }
    } else if (status != JNI_OK) {
        KMC::kmclog_e(LOG_TAG, "Failed to get JNIEnv");
        return nullptr;
    }
    return env;
}

using namespace std;

std::string encryptByJava(std::string data) {
    JNIEnv* env = getJniEnv();
    if (env == nullptr) {
        return {};
    }

    if (g_ctx.g_javaCallbackObj == nullptr) {
        // 查找Java类
        jclass localClass = env->FindClass("com/tdtech/cnp/kmcsdk/v1/KeyStoreHelper");
        if (localClass == nullptr) {
            return {};
        }

        // 创建全局引用
        jclass globalClass = (jclass) env->NewGlobalRef(localClass);
        if (globalClass == nullptr) {
            env->DeleteLocalRef(localClass);
            return {};
        }

        // 保存到全局缓存
        g_ctx.g_javaCallbackObj = globalClass;
    }

    jclass globalClass = g_ctx.g_javaCallbackObj;

    if (g_ctx.g_encryptMethodId == nullptr) {
        // 获取静态方法ID，方法返回类型为String
        jmethodID methodId = env->GetStaticMethodID(globalClass, "encryptData", "(Ljava/lang/String;)Ljava/lang/String;");
        if (methodId == nullptr) {
            return {};
        }

        // 保存到全局缓存
        g_ctx.g_encryptMethodId = methodId;
    }

    // 使用缓存的类和方法ID
    jmethodID methodId = g_ctx.g_encryptMethodId;

    // 将C++字符串转换为Java字符串
    jstring jData = env->NewStringUTF(data.c_str());
    if (jData == nullptr) {
        return {};
    }

    // 调用Java方法，返回jstring
    jstring jResult = (jstring) env->CallStaticObjectMethod(globalClass, methodId, jData);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        env->DeleteLocalRef(jData);
        return {};
    }

    // 释放Java字符串参数
    env->DeleteLocalRef(jData);

    // 将jstring转换为C++字符串
    const char* cStr = env->GetStringUTFChars(jResult, nullptr);
    if (cStr == nullptr) {
        env->DeleteLocalRef(jResult);
        return {};
    }

    string result(cStr);

    // 释放jstring资源
    env->ReleaseStringUTFChars(jResult, cStr);
    env->DeleteLocalRef(jResult);

    return result;
}

string decryptByJava(string encryptedData) {
    JNIEnv* env = getJniEnv();
    if (env == nullptr) {
        return {};
    }

    if (g_ctx.g_javaCallbackObj == nullptr) {
        // 查找Java类
        jclass localClass = env->FindClass("com/tdtech/cnp/kmcsdk/v1/KeyStoreHelper");
        if (localClass == nullptr) {
            return {};
        }

        // 创建全局引用
        jclass globalClass = (jclass) env->NewGlobalRef(localClass);
        if (globalClass == nullptr) {
            env->DeleteLocalRef(localClass);
            return {};
        }

        // 保存到全局缓存
        g_ctx.g_javaCallbackObj = globalClass;
    }

    jclass globalClass = g_ctx.g_javaCallbackObj;

    if (g_ctx.g_decryptMethodId == nullptr) {
        // 获取静态方法ID，方法返回类型为String
        jmethodID methodId = env->GetStaticMethodID(globalClass, "decryptData", "(Ljava/lang/String;)Ljava/lang/String;");
        if (methodId == nullptr) {
            return {};
        }

        // 保存到全局缓存
        g_ctx.g_decryptMethodId = methodId;
    }

    // 使用缓存的类和方法ID
    jmethodID methodId = g_ctx.g_decryptMethodId;

    // 将C++字符串转换为Java字符串
    jstring jEncryptedData = env->NewStringUTF(encryptedData.c_str());
    if (jEncryptedData == nullptr) {
        return {};
    }

    // 调用Java方法，返回jstring
    jstring jResult = (jstring) env->CallStaticObjectMethod(globalClass, methodId, jEncryptedData);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        env->DeleteLocalRef(jEncryptedData);
        return {};
    }

    // 释放Java字符串参数
    env->DeleteLocalRef(jEncryptedData);

    // 将jstring转换为C++字符串
    const char* cStr = env->GetStringUTFChars(jResult, nullptr);
    if (cStr == nullptr) {
        env->DeleteLocalRef(jResult);
        return {};
    }

    string result(cStr);

    // 释放jstring资源
    env->ReleaseStringUTFChars(jResult, cStr);
    env->DeleteLocalRef(jResult);

    return result;
}
#endif //__ANDROID__

JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_initKmc(JNIEnv *env, jobject obj,
                                                                     jboolean onlineMode,
                                                                     jint teeType,
                                                                     jboolean teeSwitch,
                                                                     jbyteArray trk,
                                                                     jint trkLen,
                                                                     jstring trkId,
                                                                     jboolean trkSwitch,
                                                                     jstring logPath,
                                                                     jstring secureStoragePath,
                                                                     jint cipherType) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    // 将Java参数转换为C++类型
    std::vector<uint8_t> trkVec;
    if (trk != nullptr) {
        trkVec.resize(trkLen);
        env->GetByteArrayRegion(trk, 0, trkLen, reinterpret_cast<jbyte*>(trkVec.data()));
    }

    const char* trkIdStr = env->GetStringUTFChars(trkId, nullptr);
    const char* logPathStr = env->GetStringUTFChars(logPath, nullptr);
    const char* secureStoragePathStr = env->GetStringUTFChars(secureStoragePath, nullptr);

    // 调用C++方法
    auto result = kmcSvc.InitKmc(
            onlineMode,
            static_cast<uint8_t>(teeType),
            teeSwitch,
            trkVec,
            trkLen,
            trkIdStr ? trkIdStr : "",
            trkSwitch,
            logPathStr ? logPathStr : "",
            secureStoragePathStr ? secureStoragePathStr : "",
            static_cast<KMC_AES_ALGORITHM>(cipherType)
    );

    // 释放资源
    if (trkIdStr) env->ReleaseStringUTFChars(trkId, trkIdStr);
    if (logPathStr) env->ReleaseStringUTFChars(logPath, logPathStr);
    if (secureStoragePathStr) env->ReleaseStringUTFChars(secureStoragePath, secureStoragePathStr);

    // 返回结果
    if (!result.success) {
        // 如果失败，可以抛出异常
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }

#ifdef __ANDROID__
    // 调用这两个接口激活java类和方法缓存
    std::string encrypted = encryptByJava("test");
    decryptByJava(encrypted);
#endif //__ANDROID__
    return result.success;
}

JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_teeSwitch(JNIEnv *env, jobject obj, jboolean teeSwitch) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    auto result = kmcSvc.TeeSwitch(teeSwitch);
    return result.success;
}

/**
 * FinalizeKmc JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_finalizeKmc(JNIEnv *env, jobject obj) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    auto result = kmcSvc.FinalizeKmc();
    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * startDownloadKeyMaterial JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_startDownloadKeyMaterial(JNIEnv *env, jobject obj,
                                                                                      jstring kmsUri,
                                                                                      jstring userUri,
                                                                                      jstring token,
                                                                                      jstring password,
                                                                                      jstring clientID,
                                                                                      jstring deviceID,
                                                                                      jstring kmsIP,
                                                                                      jstring kmsPort) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    const char* kmsUriStr = (kmsUri != nullptr) ? env->GetStringUTFChars(kmsUri, nullptr) : nullptr;
    const char* userUriStr = (userUri != nullptr) ? env->GetStringUTFChars(userUri, nullptr) : nullptr;
    const char* tokenStr = (token != nullptr) ? env->GetStringUTFChars(token, nullptr) : nullptr;
    const char* passwordStr = (password != nullptr) ? env->GetStringUTFChars(password, nullptr) : nullptr;
    const char* clientIDStr = (clientID != nullptr) ? env->GetStringUTFChars(clientID, nullptr) : nullptr;
    const char* deviceIDStr = (deviceID != nullptr) ? env->GetStringUTFChars(deviceID, nullptr) : nullptr;
    const char* kmsIPStr = (kmsIP != nullptr) ? env->GetStringUTFChars(kmsIP, nullptr) : nullptr;
    const char* kmsPortStr = (kmsPort != nullptr) ? env->GetStringUTFChars(kmsPort, nullptr) : nullptr;
    // 创建 std::string 对象
    std::string kmsUriStd = kmsUriStr ? kmsUriStr : "";
    std::string userUriStd = userUriStr ? userUriStr : "";
    std::string tokenStd = tokenStr ? tokenStr : "";
    std::string passwordStd = passwordStr ? passwordStr : "";
    std::string clientIDStd = clientIDStr ? clientIDStr : "";
    std::string deviceIDStd = deviceIDStr ? deviceIDStr : "";
    std::string kmsIPStd = kmsIPStr ? kmsIPStr : "";
    std::string kmsPortStd = kmsPortStr ? kmsPortStr : "";

    auto result = kmcSvc.StartDownloadKeyMaterial(
            kmsUriStd,
            userUriStd,
            tokenStd,
            passwordStd,
            clientIDStd,
            deviceIDStd,
            kmsIPStd,
            kmsPortStd
    );

    // 释放资源
    if (kmsUriStr) env->ReleaseStringUTFChars(kmsUri, kmsUriStr);
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);
    if (tokenStr) env->ReleaseStringUTFChars(token, tokenStr);
    if (passwordStr) env->ReleaseStringUTFChars(password, passwordStr);
    if (clientIDStr) env->ReleaseStringUTFChars(clientID, clientIDStr);
    if (deviceIDStr) env->ReleaseStringUTFChars(deviceID, deviceIDStr);
    if (kmsIPStr) env->ReleaseStringUTFChars(kmsIP, kmsIPStr);
    if (kmsPortStr) env->ReleaseStringUTFChars(kmsPort, kmsPortStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * setOfflineKeyMaterial JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_setOfflineKeyMaterial(JNIEnv *env, jobject obj,
                                                                                   jstring kmsUri,
                                                                                   jstring userUri,
                                                                                   jobject kmsCertObj,
                                                                                   jobject keyMaterialsObj) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    // 转换kmsUri和userUri
    const char* kmsUriStr = env->GetStringUTFChars(kmsUri, nullptr);
    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);

    // 转换KmsCert对象到CertInfos2
    KMC::CertInfos2 certInfos2;
    jclass kmsCertClass = env->GetObjectClass(kmsCertObj);

    // 获取KmsCert的各个字段
    jmethodID getKmsUriMethod = env->GetMethodID(kmsCertClass, "getKmsUri", "()Ljava/lang/String;");
    jmethodID getCertUriMethod = env->GetMethodID(kmsCertClass, "getCertUri", "()Ljava/lang/String;");
    jmethodID getValidFromMethod = env->GetMethodID(kmsCertClass, "getValidFrom", "()Ljava/lang/String;");
    jmethodID getValidToMethod = env->GetMethodID(kmsCertClass, "getValidTo", "()Ljava/lang/String;");
    jmethodID getUserKeyPeriodMethod = env->GetMethodID(kmsCertClass, "getUserKeyPeriod", "()J"); // 修改为long类型
    jmethodID getUserKeyOffsetMethod = env->GetMethodID(kmsCertClass, "getUserKeyOffset", "()J"); // 修改为long类型
    jmethodID getPubEncKeyMethod = env->GetMethodID(kmsCertClass, "getPubEncKey", "()Ljava/lang/String;");
    jmethodID getPubAuthKeyMethod = env->GetMethodID(kmsCertClass, "getPubAuthKey", "()Ljava/lang/String;");

    // 获取字段值
    jstring kmsUriCertStr = (jstring) env->CallObjectMethod(kmsCertObj, getKmsUriMethod);
    jstring certUriStr = (jstring) env->CallObjectMethod(kmsCertObj, getCertUriMethod);
    jstring validFromStr = (jstring) env->CallObjectMethod(kmsCertObj, getValidFromMethod);
    jstring validToStr = (jstring) env->CallObjectMethod(kmsCertObj, getValidToMethod);
    jlong userKeyPeriod = env->CallLongMethod(kmsCertObj, getUserKeyPeriodMethod); // 直接获取long类型
    jlong userKeyOffset = env->CallLongMethod(kmsCertObj, getUserKeyOffsetMethod); // 直接获取long类型
    jstring pubEncKeyStr = (jstring) env->CallObjectMethod(kmsCertObj, getPubEncKeyMethod);
    jstring pubAuthKeyStr = (jstring) env->CallObjectMethod(kmsCertObj, getPubAuthKeyMethod);

    // 转换为C++字符串
    const char* kmsUriCert = env->GetStringUTFChars(kmsUriCertStr, nullptr);
    const char* certUri = env->GetStringUTFChars(certUriStr, nullptr);
    const char* validFrom = env->GetStringUTFChars(validFromStr, nullptr);
    const char* validTo = env->GetStringUTFChars(validToStr, nullptr);
    const char* pubEncKey = env->GetStringUTFChars(pubEncKeyStr, nullptr);
    const char* pubAuthKey = env->GetStringUTFChars(pubAuthKeyStr, nullptr);

    // 填充CertInfos2结构体
    certInfos2.kmsUri = kmsUriCert ? kmsUriCert : "";
    certInfos2.certUri = certUri ? certUri : "";
    certInfos2.validFrom = validFrom ? validFrom : "";
    certInfos2.validTo = validTo ? validTo : "";
    certInfos2.userKeyPeriod = userKeyPeriod; // 直接赋值
    certInfos2.userKeyOffset = userKeyOffset; // 直接赋值
    certInfos2.pubEncKey = pubEncKey ? pubEncKey : "";
    certInfos2.pubAuthKey = pubAuthKey ? pubAuthKey : "";

    // 释放资源
    if (kmsUriCert) env->ReleaseStringUTFChars(kmsUriCertStr, kmsUriCert);
    if (certUri) env->ReleaseStringUTFChars(certUriStr, certUri);
    if (validFrom) env->ReleaseStringUTFChars(validFromStr, validFrom);
    if (validTo) env->ReleaseStringUTFChars(validToStr, validTo);
    if (pubEncKey) env->ReleaseStringUTFChars(pubEncKeyStr, pubEncKey);
    if (pubAuthKey) env->ReleaseStringUTFChars(pubAuthKeyStr, pubAuthKey);

    // 转换KeyMaterials对象到KeyInfos2
    jclass keyMaterialsClass = env->GetObjectClass(keyMaterialsObj);
    jmethodID getKeyMaterialsMethod = env->GetMethodID(keyMaterialsClass, "getKeyMaterials", "()Ljava/util/List;");
    jobject keyMaterialsList = env->CallObjectMethod(keyMaterialsObj, getKeyMaterialsMethod);

    // 遍历List<UserKeyMaterial>
    jclass listClass = env->FindClass("java/util/List");
    jmethodID listSizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID listGetMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    int size = env->CallIntMethod(keyMaterialsList, listSizeMethod);
    std::vector<KMC::KeyInfos2> keyInfos;

    KMC::kmclog_i(LOG_TAG, "in list size:%d", size);
//    keyInfos.reserve(size);
    for (int i = 0; i < size; ++i) {
        jobject userKeyMaterialObj = env->CallObjectMethod(keyMaterialsList, listGetMethod, i);

        // 获取UserKeyMaterial的各个字段
        jclass userKeyMaterialClass = env->GetObjectClass(userKeyMaterialObj);
        jmethodID getKmsUriMethod = env->GetMethodID(userKeyMaterialClass, "getKmsUri", "()Ljava/lang/String;");
        jmethodID getCertUriMethod = env->GetMethodID(userKeyMaterialClass, "getCertUri", "()Ljava/lang/String;");
        jmethodID getSskMethod = env->GetMethodID(userKeyMaterialClass, "getSsk", "()Ljava/lang/String;");
        jmethodID getRskMethod = env->GetMethodID(userKeyMaterialClass, "getRsk", "()Ljava/lang/String;");
        jmethodID getPvtMethod = env->GetMethodID(userKeyMaterialClass, "getPvt", "()Ljava/lang/String;");
        jmethodID getDateMethod = env->GetMethodID(userKeyMaterialClass, "getDate", "()Ljava/lang/String;");
        jmethodID getValidFromMethod = env->GetMethodID(userKeyMaterialClass, "getValidFrom", "()Ljava/lang/String;");
        jmethodID getValidToMethod = env->GetMethodID(userKeyMaterialClass, "getValidTo", "()Ljava/lang/String;");
        jmethodID getUidMethod = env->GetMethodID(userKeyMaterialClass, "getUid", "()Ljava/lang/String;");
        jmethodID getPeriodNoMethod = env->GetMethodID(userKeyMaterialClass, "getPeriodNo", "()J");
        jmethodID getCommunityMethod = env->GetMethodID(userKeyMaterialClass, "getCommunity", "()Ljava/lang/String;");

        jstring kmsUriStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getKmsUriMethod);
        jstring certUriStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getCertUriMethod);
        jstring sskStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getSskMethod);
        jstring rskStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getRskMethod);
        jstring pvtStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getPvtMethod);
        jstring dateStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getDateMethod);
        jstring validFromStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getValidFromMethod);
        jstring validToStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getValidToMethod);
        jstring uidStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getUidMethod);
        jlong periodNo = (jlong) env->CallLongMethod(userKeyMaterialObj, getPeriodNoMethod);
        jstring communityStr = (jstring) env->CallObjectMethod(userKeyMaterialObj, getCommunityMethod);

        // 转换为C++字符串
        const char* kmsUri = env->GetStringUTFChars(kmsUriStr, nullptr);
        const char* certUri = env->GetStringUTFChars(certUriStr, nullptr);
        const char* ssk = env->GetStringUTFChars(sskStr, nullptr);
        const char* rsk = env->GetStringUTFChars(rskStr, nullptr);
        const char* pvt = env->GetStringUTFChars(pvtStr, nullptr);
        const char* date = env->GetStringUTFChars(dateStr, nullptr);
        const char* validFrom = env->GetStringUTFChars(validFromStr, nullptr);
        const char* validTo = env->GetStringUTFChars(validToStr, nullptr);
        const char* uid = env->GetStringUTFChars(uidStr, nullptr);
        const char* community = env->GetStringUTFChars(communityStr, nullptr);

        // 填充KeyInfos2结构体
        KMC::KeyInfos2 material;
        material.kmsUri = kmsUri ? kmsUri : "";
        material.certUri = certUri ? certUri : "";
        material.ssk = ssk ? ssk : "";
        material.rsk = rsk ? rsk : "";
        material.pvt = pvt ? pvt : "";
        material.validFrom = validFrom ? validFrom : "";
        material.validTo = validTo ? validTo : "";
        material.userID = uid ? uid : "";
        material.keyPeriodNo = periodNo;
        material.userUri = userUriStr;
        keyInfos.push_back(material);

        // 释放资源
        if (kmsUri) env->ReleaseStringUTFChars(kmsUriStr, kmsUri);
        if (certUri) env->ReleaseStringUTFChars(certUriStr, certUri);
        if (ssk) env->ReleaseStringUTFChars(sskStr, ssk);
        if (rsk) env->ReleaseStringUTFChars(rskStr, rsk);
        if (pvt) env->ReleaseStringUTFChars(pvtStr, pvt);
        if (date) env->ReleaseStringUTFChars(dateStr, date);
        if (validFrom) env->ReleaseStringUTFChars(validFromStr, validFrom);
        if (validTo) env->ReleaseStringUTFChars(validToStr, validTo);
        if (uid) env->ReleaseStringUTFChars(uidStr, uid);
        if (community) env->ReleaseStringUTFChars(communityStr, community);

    }

    std::string kmsUriStd = kmsUriStr ? kmsUriStr : "";
    std::string userUriStd = userUriStr ? userUriStr : "";
    KMC::kmclog_i(LOG_TAG, "keyInfos size:%d", keyInfos.size());
    // 调用C++方法
    auto result = kmcSvc.SetOfflineKeyMaterial(
            kmsUriStd,
            userUriStd,
            certInfos2,
            keyInfos
    );

    // 释放资源
    if (kmsUriStr) env->ReleaseStringUTFChars(kmsUri, kmsUriStr);
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * setOfflineKeyMaterialEncry JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_setOfflineKeyMaterialEncry(JNIEnv *env, jobject obj,
                                                                                           jstring ciphertext,
                                                                                           jstring secretkey,
                                                                                           jint encryType) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    if (ciphertext == nullptr || secretkey == nullptr) {
        KMC::kmclog_w(LOG_TAG, "ciphertext or secretkey is null");
        return false;
    }

    // 转换ciphertext和secretkey
    const char* ciphertextStr = env->GetStringUTFChars(ciphertext, nullptr);
    const char* secretkeyStr = env->GetStringUTFChars(secretkey, nullptr);

    // 转换encryType为枚举类型
    KMC::KmcMaterialEncryType type = static_cast<KMC::KmcMaterialEncryType>(encryType);

    // 调用C++方法
    auto result = kmcSvc.SetOfflineKeyMaterialEncry(
            ciphertextStr ? ciphertextStr : "",
            secretkeyStr ? secretkeyStr : "",
            type
    );

    // 释放资源
    if (ciphertextStr) env->ReleaseStringUTFChars(ciphertext, ciphertextStr);
    if (secretkeyStr) env->ReleaseStringUTFChars(secretkey, secretkeyStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * CertRefreshPollingToggle JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_certRefreshPollingToggle(JNIEnv *env, jobject obj,
                                                                                         jstring userUri,
                                                                                         jboolean switchOn,
                                                                                         jlong certUpdatePeriod) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    // 将jstring转换为std::string
    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    std::string userUriCpp(userUriStr);
    env->ReleaseStringUTFChars(userUri, userUriStr);

    // 调用C++方法
    auto result = kmcSvc.CertRefreshPollingToggle(
            userUriCpp,
            static_cast<bool>(switchOn),
            static_cast<uint64_t>(certUpdatePeriod)
    );

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * StopDownloadKeyMaterial JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_stopDownloadKeyMaterial(JNIEnv *env, jobject obj, jstring userUri) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    std::string userUriStd = userUriStr ? userUriStr : "";

    auto result = kmcSvc.StopDownloadKeyMaterial(userUriStd);

    // 释放资源
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * SetGmkList JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_setGmkList(JNIEnv *env, jobject obj,
                                                                           jstring kmsUri,
                                                                           jstring userUri,
                                                                           jobject mikeysList) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::kmclog_i(LOG_TAG, "Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_setGmkList");

    // 转换kmsUri和userUri
    const char* kmsUriStr = env->GetStringUTFChars(kmsUri, nullptr);
    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    std::string kmsUriStd = kmsUriStr ? kmsUriStr : "";
    std::string userUriStd = userUriStr ? userUriStr : "";

    // 转换mikeysList为std::vector<GroupMikeyRequest>
    std::vector<KMC::GroupMikeyRequest> mikeys;
    jclass listClass = env->FindClass("java/util/List");
    jmethodID listSizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID listGetMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    int size = env->CallIntMethod(mikeysList, listSizeMethod);
    for (int i = 0; i < size; ++i) {
        jobject mikeyObj = env->CallObjectMethod(mikeysList, listGetMethod, i);
        jclass mikeyClass = env->GetObjectClass(mikeyObj);

        // 获取GroupMikeyRequest的各个字段
        jmethodID getKmsUriMethod = env->GetMethodID(mikeyClass, "getGmsUri", "()Ljava/lang/String;");
        jmethodID getUserUriMethod = env->GetMethodID(mikeyClass, "getUserUri", "()Ljava/lang/String;");
        jmethodID getGroupIdMethod = env->GetMethodID(mikeyClass, "getGroupId", "()Ljava/lang/String;");
        jmethodID getEtagMethod = env->GetMethodID(mikeyClass, "geteTag", "()Ljava/lang/String;");
        jmethodID getMikeyMethod = env->GetMethodID(mikeyClass, "getMikey", "()Ljava/lang/String;");

        jstring gmsUriStr = (jstring) env->CallObjectMethod(mikeyObj, getKmsUriMethod);
        jstring userUriStr = (jstring) env->CallObjectMethod(mikeyObj, getUserUriMethod);
        jstring groupIdStr = (jstring) env->CallObjectMethod(mikeyObj, getGroupIdMethod);
        jstring etagStr = (jstring) env->CallObjectMethod(mikeyObj, getEtagMethod);
        jstring mikeyStr = (jstring) env->CallObjectMethod(mikeyObj, getMikeyMethod);

        const char* gmsUri = env->GetStringUTFChars(gmsUriStr, nullptr);
        const char* userUri = env->GetStringUTFChars(userUriStr, nullptr);
        const char* groupId = env->GetStringUTFChars(groupIdStr, nullptr);
        const char* etag = env->GetStringUTFChars(etagStr, nullptr);
        const char* mikey = env->GetStringUTFChars(mikeyStr, nullptr);

        KMC::GroupMikeyRequest request;
        request.gmsUri = gmsUri ? gmsUri : "";
        request.userUri = userUri ? userUri : "";
        request.groupId = groupId ? groupId : "";
        request.eTag = etag ? etag : "";
        request.mikey = mikey ? mikey : "";

        mikeys.push_back(request);

        // 释放资源
        if (gmsUri) env->ReleaseStringUTFChars(gmsUriStr, gmsUri);
        if (userUri) env->ReleaseStringUTFChars(userUriStr, userUri);
        if (groupId) env->ReleaseStringUTFChars(groupIdStr, groupId);
        if (etag) env->ReleaseStringUTFChars(etagStr, etag);
        if (mikey) env->ReleaseStringUTFChars(mikeyStr, mikey);
    }

    KMC::kmclog_i(LOG_TAG, "before call kmcSvc.SetGmkList, userUri:%s, GroupMikey size:%d", userUriStd.c_str(), mikeys.size());
    // 调用C++方法
    auto result = kmcSvc.SetGmkList(kmsUriStd, userUriStd, mikeys);

    // 释放资源
    if (kmsUriStr) env->ReleaseStringUTFChars(kmsUri, kmsUriStr);
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * DeleteGmk JNI方法实现
 */
JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_deleteGmk(JNIEnv *env, jobject obj,
                                                                          jstring userUri,
                                                                          jstring groupId) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    const char* groupIdStr = env->GetStringUTFChars(groupId, nullptr);
    std::string userUriStd = userUriStr ? userUriStr : "";
    std::string groupIdStd = groupIdStr ? groupIdStr : "";

    auto result = kmcSvc.DeleteGmk(userUriStd, groupIdStd);

    // 释放资源
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);
    if (groupIdStr) env->ReleaseStringUTFChars(groupId, groupIdStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
    }
    return result.success;
}

/**
 * GetGmkList JNI方法实现
 */
JNIEXPORT jobject JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_getGmkList(JNIEnv *env, jobject obj,
                                                                          jstring userUri,
                                                                          jstring groupId) {
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();

    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    const char* groupIdStr = env->GetStringUTFChars(groupId, nullptr);
    std::string userUriStd = userUriStr ? userUriStr : "";
    std::string groupIdStd = groupIdStr ? groupIdStr : "";

    auto result = kmcSvc.GetGmkList(userUriStd, groupIdStd);

    // 释放资源
    if (userUriStr) env->ReleaseStringUTFChars(userUri, userUriStr);
    if (groupIdStr) env->ReleaseStringUTFChars(groupId, groupIdStr);

    if (!result.success) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), result.errorMessage.c_str());
        return nullptr;
    }

    // 将std::vector<GroupEtag>转换为Java List
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject list = env->NewObject(listClass, listConstructor);

    jclass groupEtagClass = env->FindClass("com/tdtech/cnp/kmcsdk/v1/entity/GroupEtag");
    jmethodID groupEtagConstructor = env->GetMethodID(groupEtagClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");

    for (const auto& etag : result.data) {
        jstring groupId = env->NewStringUTF(etag.groupId.c_str());
        jstring etagValue = env->NewStringUTF(etag.etag.c_str());

        jobject etagObj = env->NewObject(groupEtagClass, groupEtagConstructor, groupId, etagValue);

        jmethodID addMethod = env->GetMethodID(listClass, "add", "(Ljava/lang/Object;)Z");
        env->CallBooleanMethod(list, addMethod, etagObj);

        // 释放局部引用
        env->DeleteLocalRef(userUri);
        env->DeleteLocalRef(groupId);
        env->DeleteLocalRef(etagValue);
        env->DeleteLocalRef(etagObj);
    }

    return list;
}

JNIEXPORT jlong JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_createSession(JNIEnv* env, jobject thiz,
                                                                           jstring kmsUri, jstring userUri, jint type, jint scopeType,
                                                                           jobject p2pInfo, jobject groupInfo, jstring mikey, jint ssrcv) {

    // 获取Java字符串的UTF-8字符数组
    const char* kmsUriStr = env->GetStringUTFChars(kmsUri, nullptr);
    const char* userUriStr = env->GetStringUTFChars(userUri, nullptr);
    const char* mikeyStr = env->GetStringUTFChars(mikey, nullptr);

    // 初始化P2PInfo结构
    KMC::P2PInfo p2p;
    if (p2pInfo != nullptr) {
        // 获取P2PInfo类
        jclass p2pClass = env->GetObjectClass(p2pInfo);
        if (p2pClass == nullptr) {
            // 如果无法获取类，抛出异常
            jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(exceptionClass, "Failed to get P2PInfo class");
            return 0;
        }

        // 获取方法ID
        jmethodID getP2PInitiatorUri = env->GetMethodID(p2pClass, "getInitiatorUri", "()Ljava/lang/String;");
        jmethodID getP2PReceiverUri = env->GetMethodID(p2pClass, "getReceiverUri", "()Ljava/lang/String;");
        jmethodID getP2PiKmsUri = env->GetMethodID(p2pClass, "getiKmsUri", "()Ljava/lang/String;");
        jmethodID getP2PrKmsUri = env->GetMethodID(p2pClass, "getrKmsUri", "()Ljava/lang/String;");

        if (getP2PInitiatorUri == nullptr || getP2PReceiverUri == nullptr || getP2PiKmsUri == nullptr || getP2PrKmsUri == nullptr) {
            // 如果无法获取方法ID，抛出异常
            jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(exceptionClass, "Failed to get P2PInfo method IDs");
            return 0;
        }

        // 调用Java方法获取字符串
        jstring initiatorUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PInitiatorUri);
        jstring receiverUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PReceiverUri);
        jstring iKmsUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PiKmsUri);
        jstring rKmsUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PrKmsUri);

        // 获取UTF-8字符数组
        const char* initiatorUriStr = env->GetStringUTFChars(initiatorUri, nullptr);
        const char* receiverUriStr = env->GetStringUTFChars(receiverUri, nullptr);
        const char* iKmsUriStr = env->GetStringUTFChars(iKmsUri, nullptr);
        const char* rKmsUriStr = env->GetStringUTFChars(rKmsUri, nullptr);

        // 赋值给P2PInfo结构
        p2p.initiatorUri = initiatorUriStr;
        p2p.receiverUri = receiverUriStr;
        p2p.iKmsUri = iKmsUriStr;
        p2p.rKmsUri = rKmsUriStr;

        // 释放资源
        env->ReleaseStringUTFChars(initiatorUri, initiatorUriStr);
        env->ReleaseStringUTFChars(receiverUri, receiverUriStr);
        env->ReleaseStringUTFChars(iKmsUri, iKmsUriStr);
        env->ReleaseStringUTFChars(rKmsUri, rKmsUriStr);

        // 释放Java对象
        env->DeleteLocalRef(initiatorUri);
        env->DeleteLocalRef(receiverUri);
        env->DeleteLocalRef(iKmsUri);
        env->DeleteLocalRef(rKmsUri);
    } else {
        // 如果p2pInfo为null，初始化为空字符串
        p2p.initiatorUri = "";
        p2p.receiverUri = "";
        p2p.iKmsUri = "";
        p2p.rKmsUri = "";
    }

    // 初始化GroupInfo结构
    KMC::GroupInfo group;
    if (groupInfo != nullptr) {
        // 获取GroupInfo类
        jclass groupClass = env->GetObjectClass(groupInfo);
        if (groupClass == nullptr) {
            // 如果无法获取类，抛出异常
            jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(exceptionClass, "Failed to get GroupInfo class");
            return 0;
        }

        // 获取方法ID
        jmethodID getGroupId = env->GetMethodID(groupClass, "getGroupID", "()Ljava/lang/String;");
        jmethodID getUserUri = env->GetMethodID(groupClass, "getUserUri", "()Ljava/lang/String;");
        jmethodID getKmsUri = env->GetMethodID(groupClass, "getKmsUri", "()Ljava/lang/String;");

        if (getGroupId == nullptr || getUserUri == nullptr || getKmsUri == nullptr) {
            // 如果无法获取方法ID，抛出异常
            jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(exceptionClass, "Failed to get GroupInfo method IDs");
            return 0;
        }

        // 调用Java方法获取字符串
        jstring groupId = (jstring)env->CallObjectMethod(groupInfo, getGroupId);
        jstring userUriGroup = (jstring)env->CallObjectMethod(groupInfo, getUserUri);
        jstring kmsUriGroup = (jstring)env->CallObjectMethod(groupInfo, getKmsUri);

        // 获取UTF-8字符数组
        const char* groupIdStr = env->GetStringUTFChars(groupId, nullptr);
        const char* userUriGroupStr = env->GetStringUTFChars(userUriGroup, nullptr);
        const char* kmsUriGroupStr = env->GetStringUTFChars(kmsUriGroup, nullptr);

        // 赋值给GroupInfo结构
        group.groupID = groupIdStr;
        group.userUri = userUriGroupStr;
        group.kmsUri = kmsUriGroupStr;

        // 释放资源
        env->ReleaseStringUTFChars(groupId, groupIdStr);
        env->ReleaseStringUTFChars(userUriGroup, userUriGroupStr);
        env->ReleaseStringUTFChars(kmsUriGroup, kmsUriGroupStr);

        // 释放Java对象
        env->DeleteLocalRef(groupId);
        env->DeleteLocalRef(userUriGroup);
        env->DeleteLocalRef(kmsUriGroup);
    } else {
        // 如果groupInfo为null，初始化为空字符串
        group.groupID = "";
        group.userUri = "";
        group.kmsUri = "";
    }

    // 释放JNI字符串资源
    env->ReleaseStringUTFChars(kmsUri, kmsUriStr);
    env->ReleaseStringUTFChars(userUri, userUriStr);
    env->ReleaseStringUTFChars(mikey, mikeyStr);

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<uint64_t> result = kmcSvc.CreateSession(
            kmsUriStr, userUriStr, (KMC::SessionType)type, (KMC::ScopeType)scopeType,
            p2p, group, mikeyStr, ssrcv);

    KMC::kmclog_i(TAG, "CreateSession result:%d, sessionId:%ld", result.success, result.data);
    if (result.success) {
        return result.data;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return 0;
    }
}

JNIEXPORT jstring JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_genNewMikey(JNIEnv* env, jobject thiz,
                                                                           jstring kmsUri, jstring userUri, jlong sessionId,
                                                                           jobject p2pInfo, jstring mo, jstring mt) {

    std::string kmsUriStr = env->GetStringUTFChars(kmsUri, nullptr);
    std::string userUriStr = env->GetStringUTFChars(userUri, nullptr);
    std::string moStr = env->GetStringUTFChars(mo, nullptr);
    std::string mtStr = env->GetStringUTFChars(mt, nullptr);

    // 从Java对象中获取P2PInfo数据
    KMC::P2PInfo p2p;
    jclass p2pClass = env->GetObjectClass(p2pInfo);
    jmethodID getP2PInitiatorUri = env->GetMethodID(p2pClass, "getInitiatorUri", "()Ljava/lang/String;");
    jmethodID getP2PReceiverUri = env->GetMethodID(p2pClass, "getReceiverUri", "()Ljava/lang/String;");
    jmethodID getP2PiKmsUri = env->GetMethodID(p2pClass, "getiKmsUri", "()Ljava/lang/String;");
    jmethodID getP2PrKmsUri = env->GetMethodID(p2pClass, "getrKmsUri", "()Ljava/lang/String;");

    jstring initiatorUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PInitiatorUri);
    jstring receiverUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PReceiverUri);
    jstring iKmsUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PiKmsUri);
    jstring rKmsUri = (jstring)env->CallObjectMethod(p2pInfo, getP2PrKmsUri);

    p2p.initiatorUri = env->GetStringUTFChars(initiatorUri, nullptr);
    p2p.receiverUri = env->GetStringUTFChars(receiverUri, nullptr);
    p2p.iKmsUri = env->GetStringUTFChars(iKmsUri, nullptr);
    p2p.rKmsUri = env->GetStringUTFChars(rKmsUri, nullptr);

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<std::string> result = kmcSvc.GenNewMikey(
            kmsUriStr, userUriStr, sessionId, p2p, moStr, mtStr);

    if (result.success) {
        return env->NewStringUTF(result.data.c_str());
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

JNIEXPORT jstring JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_getMikeyBySessionId(JNIEnv* env, jobject thiz,
                                                                                   jlong sessionId) {

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<std::string> result = kmcSvc.GetMikeyBySessionId(sessionId);

    if (result.success) {
        return env->NewStringUTF(result.data.c_str());
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_releaseSession(JNIEnv* env, jobject thiz,
                                                                               jstring userUri, jlong sessionId) {

    std::string userUriStr = env->GetStringUTFChars(userUri, nullptr);

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<bool> result = kmcSvc.ReleaseSession(userUriStr, sessionId);

    if (result.success) {
        return result.data;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return false;
    }
}

/**
 * 加密RTP数据
 */
JNIEXPORT jbyteArray JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_encryptRtp(JNIEnv* env, jobject thiz,
                                                                             jbyteArray data, jint isRtp, jlong sessionId) {
    // 将Java byte数组转换为C++ vector<uint8_t>
    jbyte* dataPtr = env->GetByteArrayElements(data, nullptr);
    jsize originalCapacity = env->GetArrayLength(data);

    // 准备可扩展的本地缓冲区
    const int maxEncryptedLength = originalCapacity + 28;
    std::vector<unsigned char> dynamicBuffer(maxEncryptedLength);
    memcpy(dynamicBuffer.data(), dataPtr, originalCapacity);
    int workingLength = originalCapacity;

    env->ReleaseByteArrayElements(data, dataPtr, 0);

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<bool> result = kmcSvc.EncryptRtp(dynamicBuffer.data(), &workingLength, isRtp, sessionId);
    KMC::kmclog_i(LOG_TAG, "encryptRtp: workingLength = %d", workingLength);

    if (result.success) {

        jbyteArray retArray = env->NewByteArray(workingLength);
        if (workingLength > maxEncryptedLength) {
            KMC::kmclog_e(LOG_TAG, "encryptSrtp: workingLength(%d) > maxEncryptedLength(%d)", workingLength, maxEncryptedLength);
        }
        env->SetByteArrayRegion(
                retArray,
                0,
                workingLength,
                reinterpret_cast<const jbyte*>(dynamicBuffer.data())
        );
        return retArray;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

/**
 * 解密SRTP数据
 */
JNIEXPORT jbyteArray JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_decryptSrtp(JNIEnv* env, jobject thiz,
                                                                              jbyteArray data, jint isRtp, jlong sessionId) {
    // 将Java byte数组转换为C++ vector<uint8_t>
    jbyte* dataBytes = env->GetByteArrayElements(data, nullptr);
    jsize dataLength = env->GetArrayLength(data);
    std::vector<uint8_t> dataVec(dataLength);
    int workingLength = dataLength;
    std::memcpy(dataVec.data(), dataBytes, dataLength);
    env->ReleaseByteArrayElements(data, dataBytes, 0);

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<bool> result = kmcSvc.DecryptSrtp(dataVec.data(), &workingLength, isRtp, sessionId);

    if (result.success) {
        // 将C++ vector<uint8_t>转换为Java byte数组
        jbyteArray javaResult = env->NewByteArray(workingLength);
        env->SetByteArrayRegion(javaResult, 0, workingLength, (jbyte*)dataVec.data());
        return javaResult;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

/**
 * 加密数据
 */
JNIEXPORT jobject JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_encryptData(JNIEnv* env, jobject thiz,
                                                                              jbyteArray data, jlong sessionId,
                                                                              jbyteArray iv) {
    // 将Java byte数组转换为C++ vector<uint8_t>
    jbyte* dataBytes = env->GetByteArrayElements(data, nullptr);
    jsize dataLength = env->GetArrayLength(data);
    std::vector<uint8_t> dataVec(dataLength);
    std::memcpy(dataVec.data(), dataBytes, dataLength);
    env->ReleaseByteArrayElements(data, dataBytes, 0);

    // 将Java iv数组转换为C++ vector<uint8_t>
    std::vector<uint8_t> ivVec;
    if (iv != nullptr) {
        jbyte* ivBytes = env->GetByteArrayElements(iv, nullptr);
        jsize ivLength = env->GetArrayLength(iv);
        ivVec = std::vector<uint8_t>(ivLength);
        std::memcpy(ivVec.data(), ivBytes, ivLength);
        env->ReleaseByteArrayElements(iv, ivBytes, 0);
    }

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<KMC::EncryptDataStruct> result = kmcSvc.EncryptData(dataVec, sessionId, ivVec);

    if (result.success) {
        // 将C++ EncryptData转换为Java EncryptData对象
        KMC::EncryptDataStruct& encryptData = result.data;

        // 创建Java EncryptData对象
        jclass encryptDataClass = env->FindClass("com/tdtech/cnp/kmcsdk/v1/entity/EncryptData");
        if (encryptDataClass == nullptr) {
            return nullptr;
        }

        // 创建对象
        jmethodID constructor = env->GetMethodID(encryptDataClass, "<init>", "()V");
        jobject javaEncryptData = env->NewObject(encryptDataClass, constructor);

        // 设置encData
        jmethodID setEncData = env->GetMethodID(encryptDataClass, "setEncData", "([B)V");
        jbyteArray encDataArray = env->NewByteArray(encryptData.data.size());
        env->SetByteArrayRegion(encDataArray, 0, encryptData.data.size(), (jbyte*)encryptData.data.data());
        env->CallVoidMethod(javaEncryptData, setEncData, encDataArray);

        // 设置dppkid
        jmethodID setDppkid = env->GetMethodID(encryptDataClass, "setDppkid", "([B)V");
        jbyteArray dppkidArray = env->NewByteArray(encryptData.dppkid.size());
        env->SetByteArrayRegion(dppkidArray, 0, encryptData.dppkid.size(), (jbyte*)encryptData.dppkid.data());
        env->CallVoidMethod(javaEncryptData, setDppkid, dppkidArray);

        // 设置algorithm
        jmethodID setAlgorithm = env->GetMethodID(encryptDataClass, "setAlgorithm", "(Lcom/tdtech/cnp/kmcsdk/v1/entity/CipherType;)V");
        jclass cipherTypeClass = env->FindClass("com/tdtech/cnp/kmcsdk/v1/entity/CipherType");
        jmethodID fromValueMethod = env->GetStaticMethodID(cipherTypeClass, "fromValue", "(I)Lcom/tdtech/cnp/kmcsdk/v1/entity/CipherType;");
        jobject cipherType = env->CallStaticObjectMethod(cipherTypeClass, fromValueMethod, static_cast<int>(encryptData.algorithm));
        env->CallVoidMethod(javaEncryptData, setAlgorithm, cipherType);

        return javaEncryptData;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

/**
 * 解密数据
 */
JNIEXPORT jbyteArray JNICALL Java_com_tdtech_cnp_kmcsdk_v1_KmcJNI_decryptData(JNIEnv* env, jobject thiz,
                                                                              jobject encryptData, jlong sessionId,
                                                                              jbyteArray iv) {
    // 将Java iv数组转换为C++ vector<uint8_t>
    std::vector<uint8_t> ivVec;
    if (iv != nullptr) {
        jbyte* ivBytes = env->GetByteArrayElements(iv, nullptr);
        jsize ivLength = env->GetArrayLength(iv);
        ivVec = std::vector<uint8_t>(ivLength);
        std::memcpy(ivVec.data(), ivBytes, ivLength);
        env->ReleaseByteArrayElements(iv, ivBytes, 0);
    }

    // 从Java EncryptData对象中获取数据
    jclass encryptDataClass = env->GetObjectClass(encryptData);

    // 获取encData
    jmethodID getEncData = env->GetMethodID(encryptDataClass, "getEncData", "()[B");
    jbyteArray encDataArray = (jbyteArray)env->CallObjectMethod(encryptData, getEncData);
    jbyte* encDataBytes = env->GetByteArrayElements(encDataArray, nullptr);
    jsize encDataLength = env->GetArrayLength(encDataArray);
    std::vector<uint8_t> encDataVec(encDataLength);
    std::memcpy(encDataVec.data(), encDataBytes, encDataLength);
    env->ReleaseByteArrayElements(encDataArray, encDataBytes, 0);


    // 创建C++ EncryptData对象
    KMC::EncryptDataStruct cppEncryptData;
    cppEncryptData.data = encDataVec;

    // 调用C++接口
    KMC::IKmcService& kmcSvc = KMC::IKmcService::GetInstance();
    KMC::Result<std::vector<uint8_t>> result = kmcSvc.DecryptData(cppEncryptData, sessionId, ivVec);

    if (result.success) {
        // 将C++ vector<uint8_t>转换为Java byte数组
        std::vector<uint8_t>& resultData = result.data;
        jbyteArray javaResult = env->NewByteArray(resultData.size());
        env->SetByteArrayRegion(javaResult, 0, resultData.size(), (jbyte*)resultData.data());
        return javaResult;
    } else {
        // 抛出异常
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, result.errorMessage.c_str());
        return nullptr;
    }
}

}