//
// Created by zWX1124406 on 2025/3/21.
//

#include "KmcContextManager.h"
#include "common-utils.h"

namespace KMC {


KmcContextManager& KmcContextManager::getInstance() {
    static KmcContextManager instance;
    return instance;
}

void KmcContextManager::addKeyMaterial(const std::string userUri, const KeyInfos keyInfo) {
    m_keyMap[buildKey(userUri, keyInfo.keyPeriodNo)] = keyInfo;
}

std::string KmcContextManager::buildKey(const std::string userUri, const int keyPeriodNo) {
    std::ostringstream oss;
    oss << userUri << keyPeriodNo;
    return oss.str();
}


Result<KeyInfos> KmcContextManager::getKeyMaterial(const std::string userUri, long timestamp) {
    if (timestamp <= 0) {
        // 获取当前时间点（系统时钟）
        auto now = std::chrono::system_clock::now();
        // 转换为从 1970-01-01 00:00:00 UTC 开始的时间间隔
        auto duration = now.time_since_epoch();
        // 将时间间隔转换为毫秒
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() / 1000L;
    }
    int keyPeriodNo = getKeyPeriodNo(timestamp);
    kmclog_i(LOG_TAG, "timestamp=%ld, keyPeriodNo=%d", timestamp, keyPeriodNo);
    // TODO 测试时先写死
    keyPeriodNo = 1494;
    kmclog_e(LOG_TAG, "There is test code, should be remove before release!!!!");
    std::string key = buildKey(userUri, keyPeriodNo);
    if (m_keyMap.find(key) != m_keyMap.end()) {
        return Result<KeyInfos>(m_keyMap[key], true, "");
    } else {
        return Result<KeyInfos>(KeyInfos(), false, "Key not found");
    }
}

int KmcContextManager::getKeyPeriodNo(long timestamp) {
    CertInfos cert = getCertificate();
    long userKeyPeriod = toLong(cert.userKeyPeriod);
    long userKeyOffset = toLong(cert.userKeyOffset);
    // 距离1900年1月1日0时的时间，单位秒
    long time = timestamp + 2208988800L;
    long p = (time - userKeyOffset) / userKeyPeriod;
    return (int) p;
}

long KmcContextManager::toLong(char value[]) {
    char* end_ptr;
    return strtol(value, &end_ptr, 10);  // 第三个参数表示进制（如10表示十进制）
}

} //KMC
