//
// Created by zWX1124406 on 2025/3/21.
//
#include "KmcSvc.h"

#include <cstdlib>
#include <cmath>

#include <chrono>
#include <algorithm>

#include "KmcLog.h"
#include "KmcContextManager.h"
#include "CacheManager.h"
#include "Sqlite3Manager.h"
#include "SqliteConnectionPool.h"
#include "KmcUtils.h"
#include "LocalDataEncryptUtils.h"
#include "GzipUtils.h"
#include "kmcTeeStorage.h"

extern "C"
{
#ifdef ENABLE_COMPILE_TEE
#include "tee/kmc-tee.h"
#endif
#include "open-source-module/base64.h"
#include "kmc-core.h"
#include "native-logic.h"
}


namespace KMC {

bool KmcSvc::InitTee(bool teeSwitch, uint8_t tee_type)
{
#ifdef ENABLE_COMPILE_TEE
    kmclog_i(LOG_TAG, "jni_teeInit, teeType = %d", KMC_TEE_QSEE);
    tee_init(tee_type);
    if (teeSwitch) {
        tee_set_switch(KMC_TEE_SWITCH_OPEN);
    } else {
        tee_set_switch(KMC_TEE_SWITCH_CLOSE);
    }
    if (OPEN_TEE_TEST)
    {
        kmclog_i(LOG_TAG, "jni_teeInit, run tee_test");
        tee_test();
    }
    kmclog_i(LOG_TAG, "jni_teeInit, end");
    return true;
#else
    if (teeSwitch) {
        kmclog_i(LOG_TAG, "jni_teeInit, not ENABLE_COMPILE_TEE");
        return false;
    }
    return true;
#endif
}

Result<bool> KmcSvc::InitKmc(bool onlineMode,
                             uint8_t teeType,
                             bool teeSwitch,
                             const std::vector<uint8_t> &trk,
                             int trkLen,
                             const std::string &trkId,
                             bool trkSwitch,
                             const std::string &logPath,
                             const std::string &secureStoragePath,
                             int cipherType)
{   
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    // 先初始化日志，否则不能调用日志功能
    if (logPath.empty())
    {
        KmcLog::init();
    }
    else
    {
        KmcLog::init(logPath.c_str());
    }

    if (kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "already inited.");
        return Result<bool>(false, false, "Kmc is already inited");
    }

    // 设置KMC环境
    kmcContextManager.SetTee(teeType);
    kmcContextManager.SetOnlineMode(static_cast<OnlineMode>(onlineMode));
    kmcContextManager.setKmcAesAlgorithm(static_cast<KMC_AES_ALGORITHM>(cipherType));

    // 设置数据库和华为kmc路径
	std::string DblDbPath = secureStoragePath + "/db/kmcSqlite.db";
    std::string ConfigPath = secureStoragePath + "/config";
	if (!DblDbPath.empty() && !ConfigPath.empty()) {
		KmcContextManager::getInstance().SetDBPath(DblDbPath);
        KmcContextManager::getInstance().SetConfigPath(ConfigPath);
	} else {
		kmclog_e(LOG_TAG, "dbPath And ConfigPath is empty");
		return Result<bool>(false, false, "dbPath And ConfigPath is empty");
	}

#ifndef __ANDROID__
    // 初始化华为kmc
    LocalDataEncrypt& hwKmc = LocalDataEncrypt::GetInstance();
    if (hwKmc.Initialize() != HuaweiKmcCode::KMC_SUCCESS) {
        kmclog_e(LOG_TAG, "failed inited HWKmc");
        return Result<bool>(false, false, "failed inited HWKmc");
    }
#endif

	// 初始化数据库连接池
    ConnectionPoolConfig poolConfig;
    poolConfig.initial_size = 3;
    poolConfig.max_size = 10;
    poolConfig.min_size = 1;
    poolConfig.idle_timeout = std::chrono::seconds(300);
    poolConfig.acquire_timeout = std::chrono::seconds(30);

    if (!SqliteConnectionPool::GetInstance().Initialize(DblDbPath, poolConfig)) {
        kmclog_e(LOG_TAG, "Failed to initialize database connection pool");
        return Result<bool>(false, false, "Failed to initialize database connection pool");
    }

    kmclog_i(LOG_TAG, "Database connection pool initialized successfully");

    // 初始化数据库表
    SqliteDatabase sqliteDb;
    if (!sqliteDb.InitializeTables()) {
        kmclog_e(LOG_TAG, "Failed to initialize database tables");
        SqliteConnectionPool::GetInstance().Shutdown();
        return Result<bool>(false, false, "Failed to initialize database tables");
    }

    // 处理TEE
    if (!InitTee(teeSwitch, teeType))
    {
        kmclog_e(LOG_TAG, "TEE initialization failed");
        return Result<bool>(false, false, "TEE initialization failed");
    }
    
    // 初始化EccsiSakke模块
    initEccsiSakke();

    // 分配内存
    if (!Init())
    {
        kmclog_e(LOG_TAG, "Failed to initialize KMC services");
        return Result<bool>(false, false, "Failed to initialize KMC services");
    }

    kmcContextManager.SetInited(true);
    kmclog_i(LOG_TAG, "KMC initialization successful");

    return Result<bool>(true, true, "");
}

Result<bool> KmcSvc::TeeSwitch(bool teeSwitch) {
#ifdef ENABLE_COMPILE_TEE
    kmclog_i(LOG_TAG, "teeSwitch, teeSwitch = %d", teeSwitch);
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    kmcContextManager.SetTee(teeSwitch);
    if (teeSwitch) {
        tee_set_switch(KMC_TEE_SWITCH_OPEN);
    } else {
        tee_set_switch(KMC_TEE_SWITCH_CLOSE);
    }
    kmclog_i(LOG_TAG, "teeSwitch, end");
    return true;
#else
    kmclog_i(LOG_TAG, "jni_teeInit, not ENABLE_COMPILE_TEE");
    return false;
#endif
}

Result<bool> KmcSvc::FinalizeKmc()
{
    if (!KmcContextManager::getInstance().GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited.");
    }

    // 清理相关操作

    KmcContextManager::getInstance().SetInited(false);

	Release();
    // 关闭连接池
    SqliteConnectionPool::GetInstance().Shutdown();

#ifndef __ANDROID__
    bool retCode = LocalDataEncrypt::GetInstance().Finalize();
	if (KE_ERROR_CODE::KE_RET_SUCCESS != retCode) {
		kmclog_e(LOG_TAG,"Failed to KeFinalize! retCode %d",
				 retCode);
        return Result<bool>(false, false, "Failed to KeFinalize!");
	}
#endif

    kmclog_i(LOG_TAG, "KMC finalization successful");
    return Result<bool>(true, true, "KMC finalization successful");
}

bool KmcSvc::Init()
{
    auto cachePtr = std::make_shared<FixedCache>(CACHEMAP_SIZE);
    if(cachePtr == nullptr)
    {
        kmclog_e(LOG_TAG, "Failed to create FixedCache");
        return false;
    }

    m_sessionManagerPtr = std::make_shared<SessionManager>(cachePtr);
    if (!m_sessionManagerPtr)
    {
        kmclog_e(LOG_TAG, "Failed to create SessionManager");
        return false;
    }

    m_encryptSvcPtr = std::make_shared<EncryptSvc>(m_sessionManagerPtr);
    if (!m_encryptSvcPtr)
    {
        kmclog_e(LOG_TAG, "Failed to create EncryptSvc");
        return false;
    }

    m_kmcHttpsLoginPtr = std::make_shared<KmcHttpsLogin>();

    // 创建密钥材料调度器
    m_keyMaterialSchedulerPtr = std::make_shared<KeyMaterialScheduler>();
    if (!m_keyMaterialSchedulerPtr)
    {
        kmclog_e(LOG_TAG, "Failed to create KeyMaterialScheduler");
        return false;
    }
    
    return true;
}

bool KmcSvc::Release() {
    // 停止调度器
    if (m_keyMaterialSchedulerPtr) {
        m_keyMaterialSchedulerPtr->Stop();
        m_keyMaterialSchedulerPtr.reset();
    }

    // 释放资源
    m_encryptSvcPtr.reset();
    m_sessionManagerPtr.reset();
    m_kmcHttpsLoginPtr.reset();

    // 清理用户认证信息
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        m_userAuthMap.clear();
    }

    // 重置KMC上下文管理器
    KmcContextManager::getInstance().reset();

    return true;
}
/**
 * 证书轮询刷新开关接口
 *
 * @pram userUri 登录用户的URI，不能为空
 * @param switchOn 证书刷新轮询开关（True开启，False关闭）
 * @param certUpdatePeriod 证书刷新周期，单位分支，最小值为15分钟，默认值15
 * @return 返回操作结果，包含是否成功和错误信息
 */
Result<bool> KmcSvc::CertRefreshPollingToggle(std::string userUri,
											  bool		  switchOn,
											  uint64_t	  certUpdatePeriod)
{
    KmcContextManager &kmcContextManagerSingleton = KmcContextManager::getInstance();
    if (!kmcContextManagerSingleton.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited.");
    }

    if (userUri.empty())
    {
        kmclog_e(LOG_TAG, "userUri cannot be empty");
        return Result<bool>(false, false, "userUri cannot be empty");
    }

    // 验证证书更新周期，最小值为15分钟
    if (switchOn && certUpdatePeriod < 15)
    {
        kmclog_e(LOG_TAG, "certUpdatePeriod must be at least 15 minutes");
        return Result<bool>(false, false, "certUpdatePeriod must be at least 15 minutes");
    }

    // 构造证书更新任务的标识符
    std::string certTaskId = userUri + "_cert_update";

    if (switchOn)
    {
        // 开启证书刷新轮询
        if (!m_keyMaterialSchedulerPtr)
        {
            kmclog_e(LOG_TAG, "KeyMaterialScheduler is not initialized");
            return Result<bool>(false, false, "KeyMaterialScheduler is not initialized");
        }

        // 创建证书更新任务函数
        auto certUpdateTaskFunc = [this](const std::string& taskId) {
            ExecuteCertUpdateTask(taskId);
        };

        // 将分钟转换为秒
        std::chrono::seconds updateInterval(certUpdatePeriod * 60);

        // 添加证书更新任务（固定周期任务，不是动态调度）
        if (!m_keyMaterialSchedulerPtr->AddUserTask(certTaskId, updateInterval, certUpdateTaskFunc, false))
        {
            kmclog_e(LOG_TAG, "Failed to add certificate update task for user: %s", userUri.c_str());
            return Result<bool>(false, false, "Failed to add certificate update task");
        }

        kmclog_i(LOG_TAG, "Certificate refresh polling enabled for user: %s, period: %llu minutes", 
                 userUri.c_str(), certUpdatePeriod);
    }
    else
    {
        // 关闭证书刷新轮询
        if (m_keyMaterialSchedulerPtr && m_keyMaterialSchedulerPtr->HasUserTask(certTaskId))
        {
            if (!m_keyMaterialSchedulerPtr->RemoveUserTask(certTaskId))
            {
                kmclog_e(LOG_TAG, "Failed to remove certificate update task for user: %s", userUri.c_str());
                return Result<bool>(false, false, "Failed to remove certificate update task");
            }
        }

        kmclog_i(LOG_TAG, "Certificate refresh polling disabled for user: %s", userUri.c_str());
    }

    return Result<bool>(true, true, "Certificate refresh polling toggle successful");
}

void KmcSvc::ExecuteCertUpdateTask(const std::string& taskId)
{
    // 从任务ID中提取userUri（移除"_cert_update"后缀）
    std::string userUri = taskId;
    size_t pos = userUri.find("_cert_update");
    if (pos != std::string::npos) {
        userUri = userUri.substr(0, pos);
    }

    kmclog_i(LOG_TAG, "Executing certificate update check for user: %s", userUri.c_str());

    // 获取用户认证信息
    UserAuthInfo authInfo;
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        auto it = m_userAuthMap.find(userUri);
        if (it == m_userAuthMap.end()) {
            kmclog_w(LOG_TAG, "No auth info found for certificate update task, user: %s", userUri.c_str());
            return;
        }
        authInfo = it->second;
    }

    if (!m_kmcHttpsLoginPtr) {
        kmclog_e(LOG_TAG, "KmcHttpsLogin is not initialized");
        return;
    }

	// 检查证书是否需要更新
	bool needCertUpdate = false;
	int	 checkResult = m_kmcHttpsLoginPtr->DoCheckCertUpdate(
			 userUri, authInfo.m_token, needCertUpdate);

	if (checkResult != KMCSDK_SUCCESS) {
		kmclog_e(LOG_TAG,
				 "Certificate update check failed for user: %s, result: %d",
				 userUri.c_str(), checkResult);
		return;
	}

	if (needCertUpdate) {
		kmclog_i(LOG_TAG,
				 "Certificate update needed for user: %s, starting download...",
				 userUri.c_str());

		// 下载新证书
		int downloadResult =
				m_kmcHttpsLoginPtr->DoDownloadCert(userUri, authInfo.m_token);

		if (downloadResult != KMCSDK_SUCCESS) {
			kmclog_e(LOG_TAG,
					 "Certificate download failed for user: %s, result: %d",
					 userUri.c_str(), downloadResult);
		} else {
			kmclog_i(LOG_TAG, "Certificate download successful for user: %s",
					 userUri.c_str());
		}
	} else {
		kmclog_i(LOG_TAG, "Certificate is up to date for user: %s",
				 userUri.c_str());
	}
}

Result<bool> KmcSvc::StartDownloadKeyMaterial(std::string &kmsUri,
                                              std::string &userUri,
                                              std::string &token,
                                              std::string &password,
                                              std::string &clientID,
                                              std::string &deviceID,
                                              std::string &kmsIP,
                                              std::string &kmsPort)
{
    KmcContextManager &kmcContextManagerSingleton = KmcContextManager::getInstance();
    if(!kmcContextManagerSingleton.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited.");
    }
    if(kmcContextManagerSingleton.GetOnlineMode() != OnlineMode::ONLINE)
    {
        kmclog_e(LOG_TAG, "Kmc is not online mode.");
        return Result<bool>(false, false, "Kmc is not online mode.");
    }

    if(token.empty() && password.empty())
    {
        kmclog_e(LOG_TAG, "Token and password cannot both be empty.");
        return Result<bool>(false, false, "Token and password cannot both be empty.");
    }

    if(token.empty() && !password.empty())
    {
        //curl Basic basic64（用户+密码 )
        token = GenerateBasicToken(userUri, password);
    }
    else{
        //curl Bearer token
        token = "Bearer " + token;
    }

    if (kmsUri.empty() || userUri.empty() || kmsIP.empty() ||
        kmsPort.empty()) {
        kmclog_e(LOG_TAG, "Bad input parameters.");
        return Result<bool>(false, false, "Bad input parameters.");
    }
    uint16_t portToUint16 = 0;
    if(!KmcUtils::StringToUInt16(kmsPort, portToUint16))
    {
        kmclog_e(LOG_TAG, "kmsport error.");
        return Result<bool>(false, false, "kmsport error.");
    }
    if(m_kmcHttpsLoginPtr->InitKmc(userUri, kmsUri, kmsIP, portToUint16) != KMCSDK_SUCCESS)
    {
        kmclog_e(LOG_TAG, "Failed to initialize KMC with provided parameters.");
        return Result<bool>(false, false, "Failed to initialize KMC with provided parameters.");
    }

    // 启动调度器
    m_keyMaterialSchedulerPtr->Start();
    
    // 保存用户认证信息，用于后续的定时任务
    UserAuthInfo authInfo;
    authInfo.m_kmsUri = kmsUri;
    authInfo.m_token = token;
    authInfo.m_password = password;
    authInfo.m_clientID = clientID;
    authInfo.m_deviceID = deviceID;
    authInfo.m_kmsIP = kmsIP;
    authInfo.m_kmsPort = kmsPort;
    authInfo.m_lastValidTo = "";  // 初始为空
    
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        m_userAuthMap[userUri] = authInfo;
    }
    
    // 同步执行首次下载
    bool initialDownloadSuccess = ExecuteInitialDownload(userUri);
    
    if (initialDownloadSuccess) {
        // 首次下载成功，启动定时任务
        SchedulePeriodicDownload(userUri);
        return Result<bool>(true, true, "Key material download started successfully.");
    }
    return Result<bool>(false, false, "Initial key material download failed.");
}
 
bool KmcSvc::ExecuteInitialDownload(const std::string& userUri)
{
    UserAuthInfo authInfo;
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        auto it = m_userAuthMap.find(userUri);
        if (it == m_userAuthMap.end()) {
            kmclog_e(LOG_TAG, "No auth info found for user: %s", userUri.c_str());
            return false;
        }
        authInfo = it->second;
    }
    
    kmclog_i(LOG_TAG, "Executing initial key material download for user: %s", userUri.c_str());
    
    std::string currentToken = authInfo.m_token;
    bool downloadCertSuccess = false;
    bool downloadKeySuccess = false;

    // 重试机制：初始尝试+1次重试
    const int maxAttempts = 2;
    
    // 下载证书
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        if (m_kmcHttpsLoginPtr->DoDownloadCert(userUri, currentToken)) {
            if (attempt < maxAttempts) {
                kmclog_w(LOG_TAG, "Certificate download attempt %d failed for user: %s, will retry", 
                        attempt, userUri.c_str());
                //短暂延迟下
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                kmclog_e(LOG_TAG, "Certificate download failed after %d attempts for user: %s", 
                        maxAttempts, userUri.c_str());
            }
        } else {
            kmclog_i(LOG_TAG, "Certificate download successful on attempt %d for user: %s", 
                    attempt, userUri.c_str());
            downloadCertSuccess = true;
            break;
        }
    }
    
    // 下载密钥
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        if (m_kmcHttpsLoginPtr->DoDownloadKey(userUri, currentToken)) {
            if (attempt < maxAttempts) {
                kmclog_w(LOG_TAG, "Key download attempt %d failed for user: %s, will retry", 
                        attempt, userUri.c_str());
                //短暂延迟下
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                kmclog_e(LOG_TAG, "Key download failed after %d attempts for user: %s", 
                        maxAttempts, userUri.c_str());
            }
        } else {
            kmclog_i(LOG_TAG, "Key download successful on attempt %d for user: %s", 
                    attempt, userUri.c_str());
            downloadKeySuccess = true;
            
            // 获取最新下载的密钥材料的到期时间
            std::string latestValidTo = GetLatestKeyMaterialValidTo(userUri);
            if (!latestValidTo.empty()) {
                // 更新用户认证信息中的最后有效期
                std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
                auto it = m_userAuthMap.find(userUri);
                if (it != m_userAuthMap.end()) {
                    it->second.m_lastValidTo = latestValidTo;
                }
            }
            break;
        }
    }
    
    return downloadCertSuccess && downloadKeySuccess;
}
 
void KmcSvc::SchedulePeriodicDownload(const std::string& userUri)
{
    UserAuthInfo authInfo;
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        auto it = m_userAuthMap.find(userUri);
        if (it == m_userAuthMap.end()) {
            kmclog_e(LOG_TAG, "No auth info found for user: %s", userUri.c_str());
            return;
        }
        authInfo = it->second;
    }
    
    // 创建定时任务函数
    auto taskFunc = [this](const std::string& userUri) {
        ExecuteKeyMaterialDownload(userUri);
    };

    // 根据密钥材料的到期时间计算下次下载间隔
    std::chrono::seconds interval;
    if (!authInfo.m_lastValidTo.empty()) {
        interval = KmcUtils::CalculateNextDownloadInterval(authInfo.m_lastValidTo);
    }
    
    if (!m_keyMaterialSchedulerPtr->AddUserTask(userUri, interval, taskFunc, true)) {
        kmclog_e(LOG_TAG, "Failed to schedule periodic download for user: %s", userUri.c_str());
    } else {
        kmclog_i(LOG_TAG, "Scheduled periodic key material download for user: %s with interval %ld seconds", 
                 userUri.c_str(), interval.count());
    }
}

void KmcSvc::ExecuteKeyMaterialDownload(const std::string& userUri)
{
    UserAuthInfo authInfo;
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        auto it = m_userAuthMap.find(userUri);
        if (it == m_userAuthMap.end()) {
            kmclog_e(LOG_TAG, "No auth info found for user: %s", userUri.c_str());
            return;
        }
        authInfo = it->second;
    }
    
    kmclog_i(LOG_TAG, "Executing scheduled key material download for user: %s", userUri.c_str());
    
    std::string currentToken = authInfo.m_token;
    bool downloadSuccess = false;
    std::string latestValidTo;
    
    // // 下载证书
    // if (m_kmcHttpsLoginPtr->DoDownloadCert(userUri, currentToken)) {
    //     kmclog_e(LOG_TAG, "Scheduled certificate download failed for user: %s", userUri.c_str());
    // } else {
    //     kmclog_i(LOG_TAG, "Scheduled certificate download successful for user: %s", userUri.c_str());
    //     downloadSuccess = true;
    // }
    
    // 下载密钥
    if (m_kmcHttpsLoginPtr->DoDownloadKey(userUri, currentToken)) {
        kmclog_e(LOG_TAG, "Scheduled key download failed for user: %s", userUri.c_str());
    } else {
        kmclog_i(LOG_TAG, "Scheduled key download successful for user: %s", userUri.c_str());
        downloadSuccess = true;
        
        // 获取最新下载的密钥材料的到期时间
        latestValidTo = GetLatestKeyMaterialValidTo(userUri);
    }
    
    // 根据下载结果安排下次执行
    if (downloadSuccess && !latestValidTo.empty()) {
        // 更新用户认证信息中的最后有效期
        {
            std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
            auto it = m_userAuthMap.find(userUri);
            if (it != m_userAuthMap.end()) {
                it->second.m_lastValidTo = latestValidTo;
            }
        }
        
        // 根据新的到期时间计算下次下载间隔
        std::chrono::seconds nextInterval = KmcUtils::CalculateNextDownloadInterval(latestValidTo);
        
        // 更新定时任务
        if (!m_keyMaterialSchedulerPtr->UpdateUserInterval(userUri, nextInterval)) {
            kmclog_e(LOG_TAG, "Failed to update download interval for user: %s", userUri.c_str());
        } else {
            kmclog_i(LOG_TAG, "Updated download interval for user: %s to %ld seconds", 
                     userUri.c_str(), nextInterval.count());
        }
    } else {
        // 下载失败，15s后重试
        auto retryInterval = std::chrono::seconds(15);
        if (!m_keyMaterialSchedulerPtr->UpdateUserInterval(userUri, retryInterval)) {
            kmclog_e(LOG_TAG, "Failed to schedule retry for user: %s", userUri.c_str());
        } else {
            kmclog_i(LOG_TAG, "Scheduled retry for user: %s in %ld seconds", 
                     userUri.c_str(), retryInterval.count());
        }
    }
}

std::string KmcSvc::GetLatestKeyMaterialValidTo(const std::string& userUri)
{
    // 从缓存或数据库获取最新的密钥材料信息
    CacheManager& cache_mgr = CacheManager::GetInstance();
    std::vector<KeyInfos2> keyInfos = cache_mgr.GetCachedKeys(userUri);
    
    if (keyInfos.empty()) {
        kmclog_w(LOG_TAG, "No key materials found for user: %s", userUri.c_str());
        return "";
    }
    
    // 找到最新的到期时间
    std::string latestValidTo;
    for (const auto& keyInfo : keyInfos) {
        if (latestValidTo.empty() || keyInfo.validTo > latestValidTo) {
            latestValidTo = keyInfo.validTo;
        }
    }
    
    return latestValidTo;
}

Result<bool> KmcSvc::StopKeyMaterialUpdate(const std::string& userUri)
{
    if (userUri.empty()) {
        kmclog_e(LOG_TAG, "Invalid userUri for StopKeyMaterialUpdate");
        return Result<bool>(false, false, "Invalid userUri");
    }
    
    if (!m_keyMaterialSchedulerPtr->RemoveUserTask(userUri)) {
        kmclog_e(LOG_TAG, "Failed to remove scheduler task for user: %s", userUri.c_str());
        return Result<bool>(false, false, "Failed to remove scheduler task");
    }
    
    kmclog_i(LOG_TAG, "Stopped key material update for user: %s", userUri.c_str());
    return Result<bool>(true, true, "Key material update stopped successfully");
}

Result<bool> KmcSvc::PauseKeyMaterialUpdate(const std::string& userUri)
{
    if (userUri.empty()) {
        kmclog_e(LOG_TAG, "Invalid userUri for PauseKeyMaterialUpdate");
        return Result<bool>(false, false, "Invalid userUri");
    }
    
    if (!m_keyMaterialSchedulerPtr->PauseUserTask(userUri)) {
        kmclog_e(LOG_TAG, "Failed to pause scheduler task for user: %s", userUri.c_str());
        return Result<bool>(false, false, "Failed to pause scheduler task");
    }
    
    kmclog_i(LOG_TAG, "Paused key material update for user: %s", userUri.c_str());
    return Result<bool>(true, true, "Key material update paused successfully");
}

Result<bool> KmcSvc::ResumeKeyMaterialUpdate(const std::string& userUri)
{
    if (userUri.empty()) {
        kmclog_e(LOG_TAG, "Invalid userUri for ResumeKeyMaterialUpdate");
        return Result<bool>(false, false, "Invalid userUri");
    }
    
    if (!m_keyMaterialSchedulerPtr->ResumeUserTask(userUri)) {
        kmclog_e(LOG_TAG, "Failed to resume scheduler task for user: %s", userUri.c_str());
        return Result<bool>(false, false, "Failed to resume scheduler task");
    }
    
    kmclog_i(LOG_TAG, "Resumed key material update for user: %s", userUri.c_str());
    return Result<bool>(true, true, "Key material update resumed successfully");
}

Result<bool> KmcSvc::SetOfflineKeyMaterial(std::string &kmsUri,
                                           std::string &userUri,
                                           CertInfos2  &kmsCert,
                                           std::vector<KeyInfos2>& keyMaterials)
{
    KmcContextManager &kmcContextManagerSingleton = KmcContextManager::getInstance();
    if(kmcContextManagerSingleton.GetOnlineMode() != OnlineMode::OFFLINE)
    {
        kmclog_e(LOG_TAG ,"Online mode not support offline materials");
        return Result<bool>(false, false, "Online mode not support offline materials");
    }

    // 更新缓存
    CacheManager &cache_mgr = CacheManager::GetInstance();
    bool cache_updated = cache_mgr.TryUpdateCertificateCache(kmsCert);
    if (cache_updated) {
        kmclog_i(LOG_TAG, "Certificate cache updated successfully");
    }

    // 更新所有密钥材料缓存
    kmclog_i(LOG_TAG, "keyMaterials.size:[%d]", keyMaterials.size());
    for (const auto& keyMaterial : keyMaterials) {
        cache_updated = cache_mgr.TryUpdateKeyCache(keyMaterial);
        if (cache_updated) {
            kmclog_i(LOG_TAG, "Key cache updated successfully");
        }
    }

    uint8_t teeType = kmcContextManagerSingleton.GetTee();
	if ( teeType != KMC_TEE_TYPE::KMC_NO_TEE) {
        //tee存储证书
        KmcTeeManager::StoreCert(
				teeType, userUri, OnlineMode::OFFLINE, kmsCert.version,
				kmsCert.certUri, kmsCert.kmsUri, "", kmsCert.validFrom,
				kmsCert.validTo, kmsCert.revoked, kmsCert.userKeyPeriod,
				kmsCert.userKeyOffset, "", kmsCert.pubEncKey,
				kmsCert.pubAuthKey, "");
        // tee存储密钥
		KmcTeeManager::StoreKeyMaterialsFromCache(keyMaterials, userUri,
												  teeType, OnlineMode::OFFLINE);
        kmclog_i(LOG_TAG,
						 "Successfully stored certificate to Tee");
	} 
    else {
        // 使用连接池获取数据库连接
        SqliteDatabase sqliteDb;
		if (sqliteDb.IsAvailable()) {
			if (sqliteDb.InsertCertInfo(kmsCert, OnlineMode::OFFLINE)) {
				kmclog_i(LOG_TAG,
						 "Successfully stored certificate to database");
			} else {
				kmclog_e(LOG_TAG, "Failed to store certificate to database");
			}

			// 插入所有密钥材料到数据库
			for (const auto &keyMaterial : keyMaterials) {
				std::string encrypted_material =
						KmcEncryptKeyMaterial::EncryptKeyMaterial(keyMaterial);
				if (!encrypted_material.empty()) {
					if (sqliteDb.InsertKeyInfo(keyMaterial, OnlineMode::OFFLINE,
											   encrypted_material)) {
						kmclog_i(LOG_TAG,
								 "Successfully stored encrypted key material");
					} else {
						kmclog_e(LOG_TAG,
								 "Failed to store key material to database");
					}
				} else {
					kmclog_e(LOG_TAG, "Failed to encrypt key material");
				}
			}
		}
	}

	return Result<bool>(true, true, "Offline set cert and key materials successfully");
}

Result<bool> KmcSvc::SetOfflineKeyMaterialEncry(std::string			 ciphertext,
												std::string			 secretkey,
												KmcMaterialEncryType encryType)
{
	KmcContextManager &kmcContextManagerSingleton =
			KmcContextManager::getInstance();
	if (kmcContextManagerSingleton.GetOnlineMode() != OnlineMode::OFFLINE) {
		kmclog_e(LOG_TAG,
				 "Online mode not support offline encrypted materials");
		return Result<bool>(
				false, false,
				"Online mode not support offline encrypted materials");
	}

	if (ciphertext.empty() || secretkey.empty()) {
		kmclog_e(LOG_TAG, "Ciphertext or secretkey cannot be empty");
		return Result<bool>(false, false,
							"Ciphertext or secretkey cannot be empty");
	}

	// 步骤1: Base64解码
	// 计算解码后的最大长度
	size_t decoded_max_len = (ciphertext.length() * 3) / 4 + 1;
	std::vector<unsigned char> decoded_data(decoded_max_len);

	unsigned int decoded_len = cu_decodeBase64(
			ciphertext.c_str(), ciphertext.length(), decoded_data.data());
	if (decoded_len == 0) {
		kmclog_e(LOG_TAG, "Base64 decode failed");
		return Result<bool>(false, false, "Base64 decode failed");
	}
	decoded_data.resize(decoded_len);

    //加密时的key是密码经过sha256后的，这里保持一致
	std::string sha256Key = AesKeyWrap::sha256(secretkey);
    std::vector<uint8_t> sha256KeyBytes;
    AesKeyWrap::hexToBytes(sha256Key, sha256KeyBytes);

	// 步骤2: KW-AES256解密
	std::vector<uint8_t> encrypted_bytes;
	if (!AesKeyWrap::unwrap(sha256KeyBytes, decoded_data, encrypted_bytes)) {
		kmclog_e(LOG_TAG, "KW-AES256 unwrap failed");
		return Result<bool>(false, false, "KW-AES256 unwrap failed");
	}

	kmclog_i(LOG_TAG, "KW-AES256 unwrap successful");

	// 步骤3: GZIP解压缩
	std::string decompressed_json;
	if (!GzipUtils::Decompress(encrypted_bytes, decompressed_json)) {
		kmclog_e(LOG_TAG, "GZIP decompress failed");
		return Result<bool>(false, false, "GZIP decompress failed");
	}

	kmclog_i(LOG_TAG, "GZIP decompress successful, decompressed length: %zu",
			 decompressed_json.length());

	// 步骤4: 解析JSON获取证书和密钥材料
	CertInfos2			   kmsCert;
	std::vector<KeyInfos2> keyMaterials;
	std::string			   kmsUri, userUri;

	if (!KmcUtils::ParseEncryptedMaterial(decompressed_json, kmsCert, keyMaterials,
								kmsUri, userUri)) {
		kmclog_e(LOG_TAG, "Failed to parse decrypted material");
		return Result<bool>(false, false, "Failed to parse decrypted material");
	}

	kmclog_i(LOG_TAG, "Successfully parsed certificate and %zu key materials",
			 keyMaterials.size());

    kmclog_i(LOG_TAG, "kmsCert: %s", kmsCert.pubEncKey.c_str());

	// 步骤6: 调用SetOfflineKeyMaterial
	return SetOfflineKeyMaterial(kmsUri, userUri, kmsCert, keyMaterials);
}



Result<bool> KmcSvc::StopDownloadKeyMaterial(std::string &userUri)
{
    if (userUri.empty()) {
        kmclog_e(LOG_TAG, "Invalid userUri for stopDownloadKeyMaterial");
        return Result<bool>(false, false, "Invalid userUri");
    }
    
    // 停止定时任务
    m_keyMaterialSchedulerPtr->RemoveUserTask(userUri);
    
    // 清理用户认证信息
    {
        std::lock_guard<std::mutex> lock(m_userAuthMapMutex);
        m_userAuthMap.erase(userUri);
    }
    
    kmclog_i(LOG_TAG, "Stopped key material download for user: %s", userUri.c_str());
    return Result<bool>(true, true, "Key material download stopped successfully");
}

Result<bool> KmcSvc::SetGmkList(const std::string					  &kmsUri,
								const std::string					  &userUri,
								const std::vector<GroupMikeyRequest> &mikeys)
{
	KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "KMC is not initialized");
        return Result<bool>(false, false, "KMC is not initialized");
    }

    if (kmsUri.empty() || userUri.empty())
    {
        kmclog_e(LOG_TAG, "Invalid parameters: kmsUri or userUri is empty");
        return Result<bool>(false, false, "Invalid parameters");
    }

    // 检查证书和密钥材料是否就绪
    CacheManager& cache_mgr = CacheManager::GetInstance();
    std::vector<KeyInfos2> keyInfos = cache_mgr.GetCachedKeys(userUri);
    if (!cache_mgr.HasCachedCertificate() || keyInfos.empty())
    {
        kmclog_e(LOG_TAG, "Certificate or key material is not ready");
        return Result<bool>(false, false, "Certificate or key material is not ready");
    }

    // 遍历所有GMK并插入
    for (const auto& gmkRequest : mikeys)
    {
        bool result = InsertRawGmk(userUri, gmkRequest);
        if (!result)
        {
            kmclog_w(LOG_TAG, "Failed to insert raw GMK for group: %s", gmkRequest.groupId.c_str());
        }
    }

    kmclog_i(LOG_TAG, "Successfully processed GMK list for user: %s", userUri.c_str());
    return Result<bool>(true, true, "GMK list set successfully");
}

bool KmcSvc::InsertRawGmk(const std::string& userUri, const GroupMikeyRequest& Request)
{
    kmclog_i(LOG_TAG, "InsertRawGmk for user: %s, group: %s", userUri.c_str(), Request.groupId.c_str());
    
    SqliteDatabase sqliteDb;
    if (!sqliteDb.IsAvailable())
    {
        kmclog_e(LOG_TAG, "Database is not available");
        return false;
    }

    // 1. 删除旧的raw GMK数据
    sqliteDb.DeleteRawGmkInfo(userUri, Request.groupId, Request.eTag);

    // 2. 插入新的raw GMK数据
    RawGmkInfo rawGmkInfo;
    rawGmkInfo.userUri = userUri;
    rawGmkInfo.groupId = Request.groupId;
    rawGmkInfo.gmsUri = Request.gmsUri;
    rawGmkInfo.eTag = Request.eTag;
    rawGmkInfo.gmkMikey = Request.mikey;

    bool insertResult = sqliteDb.InsertRawGmkInfo(rawGmkInfo);
    if (!insertResult)
    {
        kmclog_e(LOG_TAG, "Failed to insert raw GMK info");
        return false;
    }

    // 3. 尝试解析GMK
    GmkInfo gmk = std::move(KmcUtils::ParseGmkByGroupMikey(userUri, rawGmkInfo.groupId, rawGmkInfo.gmkMikey));
    if (gmk.gmkId.empty())
    {
        kmclog_i(LOG_TAG, "Failed to parse GMK, keeping raw data for later processing");
        return true; // 保留原始数据，稍后可能会成功解析
    }

    // 4. 验证解析的GMK
    if (!CheckGmkValid(gmk))
    {
        kmclog_w(LOG_TAG, "Parsed GMK is not valid");
        return false;
    }

    // 5. 创建适配的GMK对象
    GmkInfo adaptedGmk;
    adaptedGmk.eTag = rawGmkInfo.eTag;
    adaptedGmk.groupId = rawGmkInfo.groupId;
    adaptedGmk.ssv = gmk.ssv;
    adaptedGmk.rand = gmk.rand;
    adaptedGmk.gukId = gmk.gukId;
    adaptedGmk.gmkId = gmk.gmkId;
    adaptedGmk.activateTime = gmk.activateTime;
    adaptedGmk.expireTime = gmk.expireTime;
    adaptedGmk.userUri = userUri;

    std::string encryptData = KmcEncryptGmk::EncryptSsvAndRand(adaptedGmk);
    // 6. 插入解析后的GMK
    bool gmkInsertResult = sqliteDb.InsertGmkInfo(adaptedGmk, encryptData);
    if (gmkInsertResult)
    {
        //删除对应的gmk缓存
        CacheManager& cache_mgr = CacheManager::GetInstance();
        cache_mgr.ClearGmkCache(adaptedGmk.userUri, adaptedGmk.groupId);
        // 删除原始数据，因为已经成功解析并存储
        sqliteDb.DeleteRawGmkInfo(userUri, Request.groupId, Request.eTag);
        kmclog_i(LOG_TAG, "Successfully processed and stored GMK");
    }
    else
    {
        kmclog_e(LOG_TAG, "Failed to insert parsed GMK");
        return false;
    }

    return true;
}

bool KmcSvc::CheckGmkValid(const GmkInfo& gmk)
{
    if (gmk.gmkId.empty())
    {
        kmclog_w(LOG_TAG, "GMK validation failed: gmkId is empty");
        return false;
    }

    if (gmk.ssv.empty())
    {
        kmclog_w(LOG_TAG, "GMK validation failed: ssv is empty");
        return false;
    }

    if (gmk.rand.empty())
    {
        kmclog_w(LOG_TAG, "GMK validation failed: rand is empty");
        return false;
    }

    return true;
}

Result<bool> KmcSvc::DeleteGmk(const std::string &userUri, const std::string &groupID)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited");
    }

    if (userUri.empty() || groupID.empty())
    {
        kmclog_e(LOG_TAG, "userUri or groupID cannot be empty");
        return Result<bool>(false, false, "userUri or groupID cannot be empty");
    }

    SqliteDatabase sqliteDb;
    if (!sqliteDb.IsAvailable())
    {
        kmclog_e(LOG_TAG, "Database is not available");
        return Result<bool>(false, false, "Database is not available");
    }

	bool result = true;

	// 删除该用户的所有GMK数据
	result &= sqliteDb.DeleteGmkInfoByUserGroup(userUri, groupID);
    result &= sqliteDb.DeleteRawGmkInfo(userUri, groupID);

    //删除缓存
    CacheManager& cache_mgr = CacheManager::GetInstance();
    cache_mgr.ClearGmkCache(userUri, groupID);
	if (result)
    {
        return Result<bool>(true, true, "GMK deleted successfully");
    }
    else
    {
        return Result<bool>(false, false, "Failed to delete GMK");
    }
}

Result<std::vector<GroupEtag>> KmcSvc::GetGmkList(const std::string &userUri, const std::string &groupID)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<std::vector<GroupEtag>>(std::vector<GroupEtag>(), false, "Kmc is not inited");
    }

    if (userUri.empty() || groupID.empty())
    {
        kmclog_e(LOG_TAG, "userUri or groupID cannot be empty");
        return Result<std::vector<GroupEtag>>(std::vector<GroupEtag>(), false, "userUri or groupID cannot be empty");
    }

    SqliteDatabase sqliteDb;
    if (!sqliteDb.IsAvailable())
    {
        kmclog_e(LOG_TAG, "Database is not available");
        return Result<std::vector<GroupEtag>>(std::vector<GroupEtag>(), false, "Database is not available");
    }

    std::vector<GroupEtag> result;

    CacheManager& cache_mgr = CacheManager::GetInstance();
    std::vector<GmkInfo> GmkInfos = cache_mgr.GetCachedGmks(userUri, groupID);
    if (GmkInfos.empty())
    {   
        kmclog_i(LOG_TAG, "No GMK entries found for user: %s and group: %s", userUri.c_str(), groupID.c_str());
        return Result<std::vector<GroupEtag>>(result, false, "No GMK entries found");
    }

    // 去重处理，每个group选取etag最大的一条
    std::map<std::string, GroupEtag> etagMap;
    for (const auto& entity : GmkInfos)
    {
        auto it = etagMap.find(entity.groupId);
        if (it == etagMap.end())
        {
            etagMap[entity.groupId] = GroupEtag{entity.groupId, entity.eTag};
        }
        else
        {
            int etag1 = strtol(entity.eTag.c_str(), nullptr, 10);
            int etag2 = strtol(it->second.etag.c_str(), nullptr, 10);
            if (etag1 > etag2)
            {
                etagMap[entity.groupId] = GroupEtag{entity.groupId, entity.eTag};
            }
        }
    }

    // 转换为vector
    for (const auto& pair : etagMap)
    {
        result.push_back(pair.second);
    }

    kmclog_i(LOG_TAG, "Retrieved %zu GMK entries for user: %s", result.size(), userUri.c_str());
    return Result<std::vector<GroupEtag>>(result, true, "");
}

Result<uint64_t> KmcSvc::CreateSession(const std::string &kmsUri,
									   const std::string &userUri,
									   SessionType		  type,
									   ScopeType		  scopeType,
									   const P2PInfo	 &p2pInfo,
									   const GroupInfo   &groupInfo,
									   const std::string &mikey,
									   int				  ssrcv)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<uint64_t>(0, false, "Kmc is not inited");
    }

    // 检查证书和密钥材料是否就绪
    CacheManager& cache_mgr = CacheManager::GetInstance();
    std::vector<KeyInfos2> keyInfos = cache_mgr.GetCachedKeys(userUri);
    if (!cache_mgr.HasCachedCertificate() || keyInfos.empty())
    {
        kmclog_e(LOG_TAG, "Certificate or key material is not ready");
        return Result<uint64_t>(0, false, "Certificate or key material is not ready");
    }

    if (kmsUri.empty() || userUri.empty())
    {
        kmclog_e(LOG_TAG, "kmsUri or userUri is empty");
        return Result<uint64_t>(0, false, "kmsUri or userUri is empty");
    }

    if (scopeType == ScopeType::P2P && p2pInfo.initiatorUri.empty())
    {
        kmclog_e(LOG_TAG, "P2P mode but p2pInfo is invalid");
        return Result<uint64_t>(0, false, "P2P mode but p2pInfo is invalid");
    }

    if (scopeType == ScopeType::GROUP && groupInfo.groupID.empty())
    {
        kmclog_e(LOG_TAG, "GROUP mode but groupInfo is invalid");
        return Result<uint64_t>(0, false, "GROUP mode but groupInfo is invalid");
    }

    //Tee模式的证书和密钥加载到内存中  非tee模式证书密钥在反序列已经加载到内存中
    if(kmcContextManager.GetTee() != KMC_TEE_TYPE::KMC_NO_TEE)
    {
        mikey_sakke_msg_t extractedEccsiSakkeMsg = KmcUtils::ExtractPtpEccsiSakkeMsgHeader(mikey);
        uint64_t timeStamp = KmcUtils::GetTimeFormMikeyMes(extractedEccsiSakkeMsg);
        KmcTeeManager::LoadCertMaterial(kmcContextManager.GetTee(), userUri, kmcContextManager.GetOnlineMode(), timeStamp);
    }

    // 准备会话参数
    std::shared_ptr<P2PInfo> p2p_info = std::make_shared<P2PInfo>(p2pInfo);
    std::shared_ptr<GroupInfo> group_info = std::make_shared<GroupInfo>(groupInfo);

    if (scopeType == ScopeType::P2P)
    {
        // 从证书缓存获取KMS URI
        const CertInfos2* certInfo = cache_mgr.GetCachedCertificate();
        if (!certInfo->certUri.empty())
        {
            p2p_info->iKmsUri = certInfo->certUri;
            p2p_info->rKmsUri = certInfo->certUri;
        }
    }


	// 调用SessionManager创建会话
    if (!m_sessionManagerPtr)
    {
        kmclog_e(LOG_TAG, "SessionManager is not initialized");
        return Result<uint64_t>(0, false, "SessionManager is not initialized");
    }

    Result<int64_t> result = m_sessionManagerPtr->createSession(
        kmsUri, userUri, type, scopeType, p2p_info, group_info, mikey, ssrcv
    );

    if (result.success && result.data > 0)
    {
        kmclog_i(LOG_TAG, "Created session successfully, session id: %lld", result.data);
        return Result<uint64_t>(static_cast<uint64_t>(result.data), true, "");
    }
    else
    {
        kmclog_e(LOG_TAG, "Failed to create session: %s", result.errorMessage.c_str());
        return Result<uint64_t>(0, false, result.errorMessage);
    }
}

Result<std::string> KmcSvc::GenNewMikey(const std::string &kmsUri,
										const std::string &userUri,
										uint64_t		   sessionId,
										const P2PInfo	  &p2pInfo,
										const std::string &mo,
										const std::string &mt)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<std::string>("", false, "Kmc is not inited");
    }

    if (kmsUri.empty() || userUri.empty() || sessionId <= 0)
    {
        kmclog_e(LOG_TAG, "Bad input parameters");
        return Result<std::string>("", false, "Bad input parameters");
    }

    if (!m_sessionManagerPtr)
    {
        kmclog_e(LOG_TAG, "SessionManager is not initialized");
        return Result<std::string>("", false, "SessionManager is not initialized");
    }

    std::shared_ptr<P2PInfo> p2p_info = std::make_shared<P2PInfo>(p2pInfo);

    Result<std::string> result = m_sessionManagerPtr->genNewMikey(
        sessionId, kmsUri, userUri, p2p_info, mo, mt
    );

    if (result.success && !result.data.empty())
    {
        kmclog_i(LOG_TAG, "Generated new mikey successfully for session: %llu", sessionId);
        return result;
    }
    else
    {
        kmclog_e(LOG_TAG, "Failed to generate new mikey: %s", result.errorMessage.c_str());
        return Result<std::string>("", false, result.errorMessage);
    }
}
 
Result<std::string> KmcSvc::GetMikeyBySessionId(uint64_t sessionId)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<std::string>("", false, "Kmc is not inited");
    }

    if (sessionId <= 0)
    {
        kmclog_e(LOG_TAG, "Invalid session id");
        return Result<std::string>("", false, "Invalid session id");
    }

    if (!m_sessionManagerPtr)
    {
        kmclog_e(LOG_TAG, "SessionManager is not initialized");
        return Result<std::string>("", false, "SessionManager is not initialized");
    }

    Result<std::string> result = m_sessionManagerPtr->getMikey(sessionId);

    if (result.success && !result.data.empty())
    {
        return result;
    }
    else
    {
        kmclog_e(LOG_TAG, "Failed to get mikey for session: %llu", sessionId);
        return Result<std::string>("", false, "Failed to get mikey");
    }
}

Result<bool> KmcSvc::ReleaseSession(const std::string &userUri, uint64_t sessionId)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited");
    }

    if (userUri.empty() || sessionId == 0)
    {
        kmclog_e(LOG_TAG, "Bad input parameters");
        return Result<bool>(false, false, "Bad input parameters");
    }

    if (!m_sessionManagerPtr)
    {
        kmclog_e(LOG_TAG, "SessionManager is not initialized");
        return Result<bool>(false, false, "SessionManager is not initialized");
    }

    Result<std::string> result = m_sessionManagerPtr->releaseSession(userUri, sessionId);

    if (result.success)
    {
        kmclog_i(LOG_TAG, "Released session successfully: %llu", sessionId);
        return Result<bool>(true, true, "Session released successfully");
    }
    else
    {
        kmclog_e(LOG_TAG, "Failed to release session: %llu", sessionId);
        return Result<bool>(false, false, "Failed to release session");
    }
}

Result<bool> KmcSvc::EncryptRtp(uint8_t* data, int* dataLen, int isRtp, uint64_t sessionId)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited");
    }

    if (data == nullptr || dataLen == nullptr || *dataLen <= 0 || *dataLen < 12 || sessionId == 0)
    {
        kmclog_e(LOG_TAG, "Invalid input parameters");
        return Result<bool>(false, false, "Invalid input parameters");
    }

    if (!m_encryptSvcPtr)
    {
        kmclog_e(LOG_TAG, "EncryptSvc is not initialized");
        return Result<bool>(false, false, "EncryptSvc is not initialized");
    }

    int originalLen = *dataLen;
    Result<bool> result = m_encryptSvcPtr->encryptSrtp(data, dataLen, isRtp, sessionId);

    if (result.success)
    {
        kmclog_i(LOG_TAG, "RTP encryption successful, original size: %d, encrypted size: %d", 
                 originalLen, *dataLen);
        return Result<bool>(true, true, "");
    }
    else
    {
        kmclog_e(LOG_TAG, "RTP encryption failed: %s", result.errorMessage.c_str());
        return Result<bool>(false, false, result.errorMessage);
    }
}

Result<bool> KmcSvc::DecryptSrtp(uint8_t* data, int* dataLen, int isRtp, uint64_t sessionId)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<bool>(false, false, "Kmc is not inited");
    }

    if (data == nullptr || dataLen == nullptr || *dataLen <= 0 || *dataLen < 12 || sessionId == 0)
    {
        kmclog_e(LOG_TAG, "Invalid input parameters");
        return Result<bool>(false, false, "Invalid input parameters");
    }

    if (!m_encryptSvcPtr)
    {
        kmclog_e(LOG_TAG, "EncryptSvc is not initialized");
        return Result<bool>(false, false, "EncryptSvc is not initialized");
    }

    int originalLen = *dataLen;
    Result<bool> result = m_encryptSvcPtr->srtpDecrypt(data, dataLen, isRtp, sessionId);

    if (result.success)
    {
        kmclog_i(LOG_TAG, "SRTP decryption successful, original size: %d, decrypted size: %d", 
                 originalLen, *dataLen);
        return Result<bool>(true, true, "");
    }
    else
    {
        kmclog_e(LOG_TAG, "SRTP decryption failed: %s", result.errorMessage.c_str());
        return Result<bool>(false, false, result.errorMessage);
    }
}

Result<struct EncryptDataStruct> KmcSvc::EncryptData(const std::vector<uint8_t> &data, uint64_t sessionId, std::vector<uint8_t> &iv)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<struct EncryptDataStruct>(KMC::EncryptDataStruct(), false, "Kmc is not inited");
    }

    if (data.empty() || sessionId == 0)
    {
        kmclog_e(LOG_TAG, "Invalid input parameters");
        return Result<struct EncryptDataStruct>(KMC::EncryptDataStruct(), false, "Invalid input parameters");
    }
    std::vector<uint8_t> dataCopy(data.begin(), data.end());

    if (!m_encryptSvcPtr)
    {
        kmclog_e(LOG_TAG, "EncryptSvc is not initialized");
        return Result<struct EncryptDataStruct>(KMC::EncryptDataStruct(), false, "EncryptSvc is not initialized");
    }

    std::vector<uint8_t> ivCopy;
    ivCopy.assign(iv.begin(), iv.end());

    Result<struct EncryptDataStruct> result = m_encryptSvcPtr->encryptData(
        (unsigned char*)dataCopy.data(), dataCopy.size(), sessionId, (unsigned char*)ivCopy.data()
    );

    if (result.success)
    {
        // 设置算法类型
        if (result.data.dppkid.empty())
        {
            // GIS场景为固定的AES 256
            result.data.algorithm = KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM;
        }
        else
        {
            result.data.algorithm = kmcContextManager.getKmcAesAlgorithm();
        }

        kmclog_i(LOG_TAG, "Data encryption successful, original size: %zu, encrypted size: %zu", 
                 dataCopy.size(), result.data.data.size());
        return result;
    }
    else
    {
        kmclog_e(LOG_TAG, "Data encryption failed: %s", result.errorMessage.c_str());
        return Result<struct EncryptDataStruct>(KMC::EncryptDataStruct(), false, result.errorMessage);
    }
}

Result<std::vector<uint8_t>> KmcSvc::DecryptData(const struct EncryptDataStruct &data,
												 uint64_t			sessionId,
												 std::vector<uint8_t> &iv)
{
    KmcContextManager& kmcContextManager = KmcContextManager::getInstance();
    if (!kmcContextManager.GetInited())
    {
        kmclog_e(LOG_TAG, "Kmc is not inited.");
        return Result<std::vector<uint8_t>>(std::vector<uint8_t>(), false, "Kmc is not inited");
    }

    if (data.data.empty() || sessionId <= 0)
    {
        kmclog_e(LOG_TAG, "Invalid input parameters");
        return Result<std::vector<uint8_t>>(std::vector<uint8_t>(), false, "Invalid input parameters");
    }

    if (!m_encryptSvcPtr)
    {
        kmclog_e(LOG_TAG, "EncryptSvc is not initialized");
        return Result<std::vector<uint8_t>>(std::vector<uint8_t>(), false, "EncryptSvc is not initialized");
    }

    std::vector<uint8_t> ivCopy;
    ivCopy.assign(iv.begin(), iv.end());
	Result<std::vector<unsigned char>> result = m_encryptSvcPtr->decryptData(
			(unsigned char *)data.data.data(), data.data.size(), sessionId,
			(unsigned char *)ivCopy.data());

	if (result.success)
    {
        kmclog_i(LOG_TAG, "Data decryption successful, encrypted size: %zu, decrypted size: %zu", 
                 data.data.size(), result.data.size());
        return Result<std::vector<uint8_t>>((result.data), true, "");
    }
    else
    {
        kmclog_e(LOG_TAG, "Data decryption failed: %s", result.errorMessage.c_str());
        return Result<std::vector<uint8_t>>(std::vector<uint8_t>(), false, result.errorMessage);
    }
}

std::string KmcSvc::GenerateBasicToken(const std::string& userUri, const std::string& password) {
    // 拼接用户名和密码
    std::string credentials = userUri + ":" + password;
    
    // 转换为UTF-8字节数组
    const unsigned char* input_data = reinterpret_cast<const unsigned char*>(credentials.c_str());
    unsigned int input_len = credentials.size();
    
    // 计算Base64输出缓冲区大小（公式: 4 * ceil(n/3)）
    unsigned int output_len = 4 * ((input_len + 2) / 3);
    char* encoded_output = new char[output_len + 1]; // +1 for null terminator
    
    // 调用Base64编码函数
    unsigned int actual_len = base64_encode(input_data, input_len, encoded_output);
    encoded_output[actual_len] = '\0'; // 确保以null结尾
    
    // 添加"Basic "前缀
    std::string result = "Basic " + std::string(encoded_output);
    
    // 释放内存
    delete[] encoded_output;
    return result;
}
} //KMC