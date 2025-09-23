//
// Created by zWX1124406 on 2025/3/21.
//

#ifndef CPP_KMCCONTEXTMANAGER_H
#define CPP_KMCCONTEXTMANAGER_H

#include <cstdint>

#include <string>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <atomic>
#include <deque>
#include <mutex>
#include <unordered_map>

#include "Commstruct.h"
#include "KmcLogInterface.h"
#include "common-utils.h"

namespace KMC {


class KmcContextManager {
public:

    KmcContextManager(KmcContextManager&&) = delete;
    KmcContextManager& operator=(KmcContextManager&&) = delete;
    KmcContextManager(const KmcContextManager&) = delete;
    KmcContextManager& operator=(const KmcContextManager&) = delete;

    static KmcContextManager& getInstance();

    void addKeyMaterial(const std::string userUri, const KeyInfos keyInfo);
    Result<KeyInfos> getKeyMaterial(const std::string userUri, long timestamp);

    std::string buildKey(const std::string userUri, const int keyPeriodNo);

    int getKeyPeriodNo(long timestamp);
    long toLong(char value[]);

    // 公共访问方法
    bool GetInited() const { return m_isInit.load(); }
    void SetInited(bool value) { m_isInit.store(value); }

    uint8_t GetTee() const { return m_isTee; }
    void SetTee(uint8_t value) { m_isTee = value ;}

    OnlineMode GetOnlineMode() const { return m_isOnlineMode; }
    void SetOnlineMode(OnlineMode value) { m_isOnlineMode = value; }

    std::string GetIP() const { return m_ip; }
    std::string GetPort() const { return m_port; }
    void SetIP(const std::string& ip) { m_ip = ip; }
    void SetPort(const std::string& port) { m_port = port; }

    void SetHttpsCertPath(std::string path){m_httpsCertPath = path;}
    std::string GetHttpsCertPath() const { return m_httpsCertPath; }

    void SetConfigPath(std::string path) { m_configPath = path; }
    std::string GetConfigPath() const { return m_configPath; }

    bool GetInitSrtp() const { return m_isInitSrtp.load(); }
    void SetInitSrtp(bool value) { m_isInitSrtp.store(value); }

    std::string GetDBPath() const {return m_dbPath; }
    void SetDBPath(std::string dbPath) { m_dbPath = dbPath; }

	CertInfos getCertificate()
	{
		if (m_certList.empty()) {
			throw std::runtime_error("Certificate list is empty");
		}
		return m_certList.front();
	}

	void addCertificate(const CertInfos cert) {
        m_certList.push_front(cert);
    }

    KMC_AES_ALGORITHM getKmcAesAlgorithm()
    {
        return m_kmcAesAlgorithm;
    }
    void setKmcAesAlgorithm(KMC_AES_ALGORITHM value)
    {
        std::lock_guard<std::mutex> lock(m_kmcMutex);
        m_kmcAesAlgorithm = value;
    }
    void reset() {
        m_isInit.store(false);
        m_isTee = false;
        m_certList.clear();
        m_keyMap.clear();
        m_ip.clear();
        m_port.clear();
        m_httpsCertPath.clear();
        m_isInitSrtp.store(false);
    }

public:
    // TODO 同步逻辑未处理
    std::atomic<bool> m_isInit;
    std::atomic<bool> m_isInitSrtp;

private:
    KmcContextManager() = default;
    ~KmcContextManager() = default;

    std::mutex m_kmcMutex;
    uint8_t m_isTee;
    OnlineMode m_isOnlineMode;
    std::deque<CertInfos> m_certList;
    std::unordered_map<std::string, KeyInfos> m_keyMap;
    std::string m_ip;
    std::string m_port;

    KMC_AES_ALGORITHM m_kmcAesAlgorithm;
    //https 证书路径
    std::string m_httpsCertPath = "";
    //华为kmc 加密路径
    std::string m_configPath = "/etc/kmc";
    //数据库路径
    std::string m_dbPath = "/var/lib/kmc/sqlite3.db";

};


} //KMC

#endif //CPP_KMCCONTEXTMANAGER_H