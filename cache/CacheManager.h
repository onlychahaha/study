#ifndef CACHE_MANAGER_H_
#define CACHE_MANAGER_H_

#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <functional>
#include <string>

#include "Commstruct.h"
#include "ReaderWriterLock.h"
#include "Sqlite3Manager.h"
#include "KmcUtils.h"

namespace KMC {

// 数据更新事件类型
enum class DataUpdateType {
    CERT_UPDATED = 0,
    KEY_UPDATED = 1,
    KEY_DELETED = 2,
    GMK_UPDATED = 3,
    GMK_DELETED = 4
};

// 数据更新事件回调函数类型
using DataUpdateCallback = std::function<void(DataUpdateType type, const std::string& userUri)>;

// 缓存管理器 - 单例模式
class CacheManager {
public:
    // 获取单例实例
    static CacheManager& GetInstance();
    
    // 禁用拷贝构造和赋值
    CacheManager(const CacheManager&) = delete;
    CacheManager& operator=(const CacheManager&) = delete;
    
    // 证书缓存操作
    bool TryUpdateCertificateCache(const CertInfos2& new_cert_info);
    const CertInfos2* GetCachedCertificate();
    bool HasCachedCertificate() const;
    
    // 密钥缓存操作  
    bool TryUpdateKeyCache(const KeyInfos2& new_key_info);
    std::vector<KeyInfos2> GetCachedKeys(const std::string& user_uri) const;
    const KeyInfos2* GetCachedKey(const std::string& user_uri, uint64_t key_period_no);
    const KeyInfos2* GetLatestCachedKey(const std::string& user_uri) const;
    bool HasCachedKey(const std::string& user_uri, uint64_t key_period_no) const;
    void ClearKeyCache(const std::string& user_uri = "");
    
    // GMK缓存操作
    bool UpdateGmkInternal(const GmkInfo& new_gmk_info);
    std::vector<GmkInfo> GetCachedGmks(const std::string& user_uri);
    std::vector<GmkInfo> GetCachedGmks(const std::string& user_uri, const std::string& group_id);
    bool HasCachedGmk(const std::string& user_uri, const std::string& group_id, const std::string& gmk_id) const;
    void ClearGmkCache(const std::string& user_uri = "", const std::string& group_id = "");
    
    // 注册数据更新回调
    void RegisterUpdateCallback(const std::string& callback_id, DataUpdateCallback callback);
    void UnregisterUpdateCallback(const std::string& callback_id);
    
    // 缓存统计信息
    size_t GetCertificateCacheSize() const;
    size_t GetKeyCacheSize() const;
    size_t GetGmkCacheSize() const;
    size_t GetGmkCacheSize(const std::string& user_uri) const;
    void PrintCacheStatistics() const;

    //密钥选择功能
    uint64_t generateKeyPeriodNo(uint64_t currentTimeSeconds, uint64_t userKeyPeriod, uint64_t userKeyOffset) const;
    std::vector<uint8_t> ExtractPtpEccsiSakkeMsgHeader(const std::string& container_base64) const;
    uint64_t ExtractMikey(const std::string& mikey_message) const;
    bool PickupKeyMaterial(const std::string& grp_mikey, const std::string& user_uri, KeyInfos2& out_key_info);
    bool PickupKeyMaterial(uint64_t timestamp, const std::string& user_uri, KeyInfos2& out_key_info);

    GmkInfo* pickGmk(const std::string& userUri, const std::string& groupNumber, uint64_t timestamp);
    GmkInfo* getLatestGmk(const std::vector<GmkInfo>& gmks);
    GmkInfo* getNearestGmk(const std::vector<GmkInfo>& gmks, uint64_t timestamp);

    // Holder访问接口（供core调用）
    KmsCertHolder* GetKmsCertHolder() const;
    UserKeyMaterialHolder* GetUserKeyMaterialHolder(const std::string& user_uri, uint64_t key_period_no) const;

private:
    static const size_t MAX_GMK_ENTRIES_PER_USER = 2000;  // 每个用户最大GMK缓存条数
    
    CacheManager() = default;
    ~CacheManager() = default;
    
    // 通知数据更新回调
    void NotifyDataUpdate(DataUpdateType type, const std::string& user_uri);
    
    // 证书比较和更新方法
    bool IsCertificateNewer(const CertInfos2& new_cert, const CertInfos2& old_cert) const;
    bool UpdateCertificateInternal(const CertInfos2& new_cert_info);
    
    // 密钥比较和更新方法
    bool IsKeyNewer(const KeyInfos2& new_key, const std::string& user_uri) const;
    bool UpdateKeyInternal(const KeyInfos2& new_key_info);
    
    // 密钥缓存key生成
    std::string GenerateKeyMapKey(const std::string& user_uri, uint64_t key_period_no) const;
    
    // GMK缓存key生成
    std::string GenerateGmkMapKey(const std::string& user_uri, const std::string& group_id, const std::string& gmk_id) const;
    std::string GenerateUserGmkPrefix(const std::string& user_uri) const;
    std::string GenerateUserGroupGmkPrefix(const std::string& user_uri, const std::string& group_id) const;
    
    // Holder缓存key生成
    std::string GenerateUserKeyMaterialHolderKey(const KeyInfos2& key_info) const;
    
    // 清理过期密钥
    void CleanupOldKeys(const std::string& user_uri, uint64_t latest_key_period_no);
    
    // 清理过期GMK，保持每个用户的GMK数量不超过限制
    void CleanupOldGmks(const std::string& user_uri);

    // 内部Holder管理方法
    void UpdateKmsCertHolder();
    void UpdateUserKeyMaterialHolder(const KeyInfos2& key_info);
    void ClearAllUserKeyMaterialHolders(const std::string& user_uri = "");

private:
    mutable ReaderWriterLock m_rwLock;  // 读写锁
    
    // 证书缓存 - 只保存一份最新的证书
    CertInfos2 m_cachedCertificate;
    bool m_hasCachedCert = false;
    
    // 密钥缓存 - key: "userUri:keyPeriodNo", value: KeyInfos2
    std::unordered_map<std::string, KeyInfos2> m_cachedKeys;
    
    // 每个用户的最新密钥周期号缓存 - key: userUri, value: latest keyPeriodNo
    std::unordered_map<std::string, uint64_t> m_latestKeyPeriods;
    
    // GMK缓存 - key: "userUri:groupId:gmkId", value: GmkInfo
    mutable std::unordered_map<std::string, GmkInfo> m_cachedGmks;
    
    // 每个用户每个组的最新GMK数据库ID缓存 - key: "userUri:groupId", value: latest database id
    mutable std::unordered_map<std::string, uint64_t> m_latestGmkDbIds;
    
    // 内部Holder缓存（自动跟随上层缓存变化）
    mutable std::unique_ptr<KmsCertHolder> m_cachedKmsCertHolder;
    mutable std::unordered_map<std::string, std::unique_ptr<UserKeyMaterialHolder>> m_cachedUserKeyMaterialHolders;
    
    // 数据更新回调
    std::unordered_map<std::string, DataUpdateCallback> m_updateCallbacks;
};

} // namespace KMC

#endif // CACHE_MANAGER_H_