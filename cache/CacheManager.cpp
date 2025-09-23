#include "CacheManager.h"
#include <algorithm>
#include <sstream>
#include <cmath>

#include "KmcContextManager.h"
#include "LocalDataEncryptUtils.h"
#include "KmcUtils.h"

extern "C"{
    #include "native-logic.h"
}

namespace KMC {

CacheManager& CacheManager::GetInstance() {
    static CacheManager instance;
    return instance;
}

bool CacheManager::TryUpdateCertificateCache(const CertInfos2 &new_cert_info)
{
	WriteLockGuard lock(m_rwLock);
    
    // 检查是否需要更新证书
    if (!m_hasCachedCert || IsCertificateNewer(new_cert_info, m_cachedCertificate)) {
        return UpdateCertificateInternal(new_cert_info);
    }
    
    kmclog_d(LOG_TAG, "Certificate is up to date, no update needed");
    return false;
}

bool CacheManager::IsCertificateNewer(const CertInfos2& new_cert, const CertInfos2& old_cert) const {
    // 比较validFrom时间字段
    if (new_cert.validFrom != old_cert.validFrom) {
        return new_cert.validFrom > old_cert.validFrom;
    }
    
    // 比较userKeyPeriod字段
    if (new_cert.userKeyPeriod != old_cert.userKeyPeriod) {
        return true; // userKeyPeriod有变化就认为需要更新
    }
    
    // 比较证书URI
    if (new_cert.certUri != old_cert.certUri) {
        return true;
    }
    
    return false;
}

bool CacheManager::UpdateCertificateInternal(const CertInfos2& new_cert_info) {
    bool was_updated = false;
    
    if (!m_hasCachedCert) {
        // 没有缓存的证书，直接添加
        kmclog_i(LOG_TAG, "No cached certificate, adding new one");
        was_updated = true;
    } else {
        // 证书更新时需要清空所有密钥数据和相关的Holder缓存
        kmclog_i(LOG_TAG, "Certificate updated, clearing all key caches and holder caches - validFrom: %s -> %s, userKeyPeriod: %llu -> %llu", 
                 m_cachedCertificate.validFrom.c_str(), new_cert_info.validFrom.c_str(),
                 m_cachedCertificate.userKeyPeriod, new_cert_info.userKeyPeriod);
        
        // 清空密钥缓存
        m_cachedKeys.clear();
        m_latestKeyPeriods.clear();
        
        // 清空所有UserKeyMaterialHolder缓存
        ClearAllUserKeyMaterialHolders();
        
        was_updated = true;
    }
    
    // 更新缓存
    m_cachedCertificate = new_cert_info;
    m_hasCachedCert = true;
    
    // 更新KmsCertHolder
    UpdateKmsCertHolder();
    
    // 通知证书更新
    NotifyDataUpdate(DataUpdateType::CERT_UPDATED, "");
    
    kmclog_i(LOG_TAG, "Certificate cache updated successfully - CertUri: %s", 
             new_cert_info.certUri.c_str());
    
    return was_updated;
}

//场景：当服务重启，离线不需要二次调用加载证书和密钥的接口，从数据库获取即可
// 在线模式的证书和密钥在二次重启，任从startdownload接口中实时获得即可
const CertInfos2* CacheManager::GetCachedCertificate() {
    // 先用读锁检查缓存
    {
        ReadLockGuard lock(m_rwLock);
        if (m_hasCachedCert) {
            return &m_cachedCertificate;
        }
        
        // 在线模式下直接返回
        KmcContextManager& context_mgr = KmcContextManager::getInstance();
        if (context_mgr.GetOnlineMode() != OnlineMode::OFFLINE) {
            return nullptr;
        }
    }
    
    // 离线模式下从数据库加载
    SqliteDatabase database;
    if (!database.IsAvailable()) {
        kmclog_e(LOG_TAG, "Database is not available for offline certificate query");
        return nullptr;
    }
    
    CertInfos2 offline_cert;
    if (!database.QueryOfflineCertInfo(offline_cert)) {
        kmclog_d(LOG_TAG, "No offline certificate found in database");
        return nullptr;
    }
    
    // 用写锁更新缓存
    WriteLockGuard write_lock(m_rwLock);
    
    // 双重检查：可能其他线程已经更新了缓存
    if (m_hasCachedCert) {
        return &m_cachedCertificate;
    }
    
    m_cachedCertificate = offline_cert;
    m_hasCachedCert = true;
    
    kmclog_i(LOG_TAG, "Offline certificate loaded from database to cache - CertUri: %s", 
             offline_cert.certUri.c_str());
    
    return &m_cachedCertificate;
}

bool CacheManager::HasCachedCertificate() const {
    ReadLockGuard lock(m_rwLock);
    return m_hasCachedCert;
}

bool CacheManager::TryUpdateKeyCache(const KeyInfos2& new_key_info) {
    WriteLockGuard lock(m_rwLock);
    
    const std::string& user_uri = new_key_info.userUri;
    
    // 检查是否需要更新密钥
    if (IsKeyNewer(new_key_info, user_uri)) {
        return UpdateKeyInternal(new_key_info);
    }
    
    kmclog_d(LOG_TAG, "Key for user %s with period %llu is not newer than cached", 
             user_uri.c_str(), new_key_info.keyPeriodNo);
    return false;
}

bool CacheManager::IsKeyNewer(const KeyInfos2& new_key, const std::string& user_uri) const {
    auto latest_it = m_latestKeyPeriods.find(user_uri);
    
    if (latest_it == m_latestKeyPeriods.end()) {
        // 没有该用户的密钥记录
        return true;
    }
    
    // 检查新密钥周期号是否更大
    return new_key.keyPeriodNo > latest_it->second;
}

bool CacheManager::UpdateKeyInternal(const KeyInfos2& new_key_info) {
    const std::string& user_uri = new_key_info.userUri;
    uint64_t new_key_period = new_key_info.keyPeriodNo;
    
    auto latest_it = m_latestKeyPeriods.find(user_uri);
    if (latest_it == m_latestKeyPeriods.end()) {
        kmclog_i(LOG_TAG, "No cached key for user %s, adding new key with period %llu", 
                 user_uri.c_str(), new_key_period);
    } else {
        kmclog_i(LOG_TAG, "Key update for user %s: period %llu -> %llu", 
                 user_uri.c_str(), latest_it->second, new_key_period);
        
        // 清理旧密钥
        CleanupOldKeys(user_uri, new_key_period);
    }
    
    // 更新缓存
    std::string cache_key = GenerateKeyMapKey(user_uri, new_key_period);
    m_cachedKeys[cache_key] = new_key_info;
    m_latestKeyPeriods[user_uri] = new_key_period;
    
    // 更新UserKeyMaterialHolder
    UpdateUserKeyMaterialHolder(new_key_info);
    
    // 通知密钥更新
    NotifyDataUpdate(DataUpdateType::KEY_UPDATED, user_uri);
    
    kmclog_i(LOG_TAG, "Key cache updated successfully - User: %s, Period: %llu", 
             user_uri.c_str(), new_key_period);
    
    return true;
}

void CacheManager::CleanupOldKeys(const std::string& user_uri, uint64_t latest_key_period_no) {
    // 查找该用户的所有密钥
    std::vector<std::string> keys_to_remove;
    
    for (const auto& pair : m_cachedKeys) {
        if (pair.second.userUri == user_uri && pair.second.keyPeriodNo < latest_key_period_no) {
            keys_to_remove.push_back(pair.first);
        }
    }
    
    // 从缓存中移除
    for (const std::string& key : keys_to_remove) {
        const KeyInfos2& key_info = m_cachedKeys[key];
        // 移除对应的UserKeyMaterialHolder
        m_cachedUserKeyMaterialHolders.erase(key);
        // 移除密钥缓存
        m_cachedKeys.erase(key);
    }
    
    if (!keys_to_remove.empty()) {
        kmclog_i(LOG_TAG, "Cleaned up %zu old keys for user: %s", keys_to_remove.size(), user_uri.c_str());
    }
}

std::string CacheManager::GenerateKeyMapKey(const std::string& user_uri, uint64_t key_period_no) const {
    return user_uri + ":" + KmcUtils::uint64ToString(key_period_no);
}

std::vector<KeyInfos2> CacheManager::GetCachedKeys(const std::string& user_uri) const {
    ReadLockGuard lock(m_rwLock);
    
    std::vector<KeyInfos2> result;
    for (const auto& pair : m_cachedKeys) {
        if (pair.second.userUri == user_uri) {
            result.push_back(pair.second);
        }
    }
    
    // 按keyPeriodNo排序
    std::sort(result.begin(), result.end(), 
              [](const KeyInfos2& a, const KeyInfos2& b) {
                  return a.keyPeriodNo < b.keyPeriodNo;
              });
    
    return result;
}

//场景：当服务重启，离线不需要二次调用加载证书和密钥的接口，从数据库获取即可
// 在线模式的证书和密钥在二次重启，任从startdownload接口中实时获得即可
const KeyInfos2* CacheManager::GetCachedKey(const std::string& user_uri, uint64_t key_period_no) {
    std::string cache_key = GenerateKeyMapKey(user_uri, key_period_no);
    
    // 先用读锁检查缓存
    {
        ReadLockGuard lock(m_rwLock);
        auto it = m_cachedKeys.find(cache_key);
        if (it != m_cachedKeys.end()) {
            return &it->second;
        }

		// 查找该用户是否有其他密钥
        // 如果没有找到指定期间号的密钥，尝试返回该用户最新的密钥
		auto latest_it = m_latestKeyPeriods.find(user_uri);
		if (latest_it != m_latestKeyPeriods.end()) {
			std::string latest_cache_key =
					GenerateKeyMapKey(user_uri, latest_it->second);
			auto latest_key_it = m_cachedKeys.find(latest_cache_key);
			if (latest_key_it != m_cachedKeys.end()) {
				kmclog_i(LOG_TAG,
						 "Expected period %llu not found for user %s, "
						 "returning latest period %llu",
						 key_period_no, user_uri.c_str(), latest_it->second);
				return &latest_key_it->second;
			}
		}

		// 在线模式下直接返回
		KmcContextManager &context_mgr = KmcContextManager::getInstance();
		if (context_mgr.GetOnlineMode() != OnlineMode::OFFLINE) {
            return nullptr;
		}
	}
    
    // 离线模式下从数据库加载
    SqliteDatabase database;
    if (!database.IsAvailable()) {
        kmclog_e(LOG_TAG, "Database is not available for key query");
        return nullptr;
    }
    
    KeyInfos2 key_info;
    std::string encrypted_data;
    if (!database.QueryKeyInfo(user_uri, key_period_no, key_info, encrypted_data)) {
        kmclog_d(LOG_TAG, "No key material found in database for user: %s, period: %llu", 
                 user_uri.c_str(), key_period_no);
        return nullptr;
    }
    
    // 解密密钥材料
    if (!encrypted_data.empty()) {
        bool result = KmcEncryptKeyMaterial::DecryptKeyMaterial(encrypted_data, key_info);
        if (!result) {
            kmclog_e(LOG_TAG, "Failed to decrypt key material from database");
            return nullptr;
        }
    }
    
    // 用写锁更新缓存
    WriteLockGuard write_lock(m_rwLock);
    
    // 双重检查：可能其他线程已经更新了缓存
    // auto it = m_cachedKeys.find(cache_key);
    // if (it != m_cachedKeys.end()) {
    //     return &it->second;
    // }
    
    // 添加到缓存
    m_cachedKeys[cache_key] = key_info;
    
    // 更新最新密钥周期记录
    auto latest_it = m_latestKeyPeriods.find(user_uri);
    if (latest_it == m_latestKeyPeriods.end() || key_period_no > latest_it->second) {
        m_latestKeyPeriods[user_uri] = key_period_no;
    }
    
    kmclog_i(LOG_TAG, "Key material loaded from database to cache - User: %s, Period: %llu", 
             user_uri.c_str(), key_period_no);
    
    return &m_cachedKeys[cache_key];
}

const KeyInfos2* CacheManager::GetLatestCachedKey(const std::string& user_uri) const {
    ReadLockGuard lock(m_rwLock);
    
    auto latest_it = m_latestKeyPeriods.find(user_uri);
    if (latest_it == m_latestKeyPeriods.end()) {
        return nullptr;
    }
    
    std::string cache_key = GenerateKeyMapKey(user_uri, latest_it->second);
    auto key_it = m_cachedKeys.find(cache_key);
    return (key_it != m_cachedKeys.end()) ? &key_it->second : nullptr;
}

bool CacheManager::HasCachedKey(const std::string& user_uri, uint64_t key_period_no) const {
    ReadLockGuard lock(m_rwLock);
    
    std::string cache_key = GenerateKeyMapKey(user_uri, key_period_no);
    return m_cachedKeys.find(cache_key) != m_cachedKeys.end();
}

void CacheManager::ClearKeyCache(const std::string& user_uri) {
    WriteLockGuard lock(m_rwLock);
    
    if (user_uri.empty()) {
        // 清空所有密钥缓存
        size_t key_count = m_cachedKeys.size();
        m_cachedKeys.clear();
        m_latestKeyPeriods.clear();
        
        // 清空所有UserKeyMaterialHolder缓存
        ClearAllUserKeyMaterialHolders();
        
        kmclog_i(LOG_TAG, "All key cache cleared, removed %zu keys", key_count);
    } else {
        // 清空指定用户的密钥缓存
        std::vector<std::string> keys_to_remove;
        
        for (const auto& pair : m_cachedKeys) {
            if (pair.second.userUri == user_uri) {
                keys_to_remove.push_back(pair.first);
            }
        }
        
        for (const std::string& key : keys_to_remove) {
            const KeyInfos2& key_info = m_cachedKeys[key];
            // 移除对应的UserKeyMaterialHolder
            m_cachedUserKeyMaterialHolders.erase(key);
            // 移除密钥缓存
            m_cachedKeys.erase(key);
        }
        
        m_latestKeyPeriods.erase(user_uri);
        
        kmclog_i(LOG_TAG, "Key cache cleared for user: %s, removed %zu keys", 
                 user_uri.c_str(), keys_to_remove.size());
    }
}

void CacheManager::RegisterUpdateCallback(const std::string& callback_id, DataUpdateCallback callback) {
    WriteLockGuard lock(m_rwLock);
    m_updateCallbacks[callback_id] = callback;
    kmclog_d(LOG_TAG, "Registered update callback: %s", callback_id.c_str());
}

void CacheManager::UnregisterUpdateCallback(const std::string& callback_id) {
    WriteLockGuard lock(m_rwLock);
    m_updateCallbacks.erase(callback_id);
    kmclog_d(LOG_TAG, "Unregistered update callback: %s", callback_id.c_str());
}

void CacheManager::NotifyDataUpdate(DataUpdateType type, const std::string& user_uri) {
    // 调用此函数时已经持有写锁
    for (const auto& pair : m_updateCallbacks) {
        try {
            pair.second(type, user_uri);
        } catch (const std::exception& e) {
            kmclog_e(LOG_TAG, "Exception in update callback %s: %s", pair.first.c_str(), e.what());
        } catch (...) {
            kmclog_e(LOG_TAG, "Unknown exception in update callback %s", pair.first.c_str());
        }
    }
}

size_t CacheManager::GetCertificateCacheSize() const {
    ReadLockGuard lock(m_rwLock);
    return m_hasCachedCert ? 1 : 0;
}

size_t CacheManager::GetKeyCacheSize() const {
    ReadLockGuard lock(m_rwLock);
    return m_cachedKeys.size();
}

//密钥选择功能实现
uint64_t CacheManager::generateKeyPeriodNo(uint64_t currentTimeSeconds, uint64_t userKeyPeriod, uint64_t userKeyOffset) const {
    if (userKeyPeriod == 0) {
        // 处理除以零的情况，返回错误值
        return 0;
    }
    
    uint64_t time = currentTimeSeconds + 2208988800LL;
    uint64_t numerator = time - userKeyOffset;
    uint64_t denominator = userKeyPeriod;
    
    // 计算除法，并使用std::floor进行向下取整
    double divisionResult = static_cast<double>(numerator) / static_cast<double>(denominator);
    int p = std::floor(divisionResult);
    
    return p;
}

std::vector<uint8_t> CacheManager::ExtractPtpEccsiSakkeMsgHeader(const std::string& container_base64) const {
    char* container_base64_c = const_cast<char*>(container_base64.c_str());

    uint8_t container_c[MAX_MESSAGE_LEN] = {0}; // 存放base64解码后的mikey message
    size_t container_len = cu_decodeBase64(container_base64_c, container_base64.length(), container_c);
    size_t msg_len_without_sign;
    mikey_sakke_msg_t extractedEccsiSakkeMsg = extractEccsiSakkeMsgWithoutVerificationDecryption(container_c, container_len, &msg_len_without_sign);

    std::vector<uint8_t> msg(MAX_MESSAGE_LEN, 0);
    size_t pt = 0;
    // extractedEccsiSakkeMsg.t.ts_value.len == 8
    memcpy(&msg[pt], extractedEccsiSakkeMsg.t.ts_value.msg, extractedEccsiSakkeMsg.t.ts_value.len);
    pt += extractedEccsiSakkeMsg.t.ts_value.len;

    msg.resize(pt);
    return msg;
}

uint64_t CacheManager::ExtractMikey(const std::string& mikey_message) const {
    if (mikey_message.empty()) {
        kmclog_e(LOG_TAG, "mikey_message is empty");
        return 0;
    }

    std::vector<uint8_t> extractedMikeyBytes = ExtractPtpEccsiSakkeMsgHeader(mikey_message);
    
    if (extractedMikeyBytes.empty()) {
        kmclog_e(LOG_TAG, "extractMikey failed - extracted bytes is empty");
        return 0;
    }

    // 解析时间戳
    uint64_t timeStamp = 0;
    int len = std::min(static_cast<int>(extractedMikeyBytes.size()), 4);
    
    if (len >= 4) {
        std::vector<uint8_t> timeStampBytes(extractedMikeyBytes.begin(), 
                                           extractedMikeyBytes.begin() + len);
        
        if (KmcUtils::IsByteArrayAllZero(timeStampBytes)) {
            timeStamp = 0;
        } else {
            uint64_t secondsFrom1900 = KmcUtils::ByteArrayToLong(timeStampBytes);
            timeStamp = secondsFrom1900 - 2208988800L; // 转换为Unix时间戳
        }
    } else {
        timeStamp = 0;
    }
    
    return timeStamp;
}

bool CacheManager::PickupKeyMaterial(const std::string& grp_mikey, const std::string& user_uri, KeyInfos2& out_key_info) {
    uint64_t timestamp = ExtractMikey(grp_mikey);
    
    PickupKeyMaterial(timestamp, user_uri, out_key_info);
    if (out_key_info.userUri.empty()) {
        kmclog_e(LOG_TAG, "PickupKeyMaterial failed - no key material found");
        return false;
    }
    return true;
    
}

bool CacheManager::PickupKeyMaterial(uint64_t			timestamp,
									 const std::string &user_uri,
									 KeyInfos2		   &out_key_info)
{
    if (timestamp == 0) {
        auto now = std::chrono::system_clock::now();
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        kmclog_i(LOG_TAG, "Fallback to current timestamp: %llu", timestamp);
    }

    // 获取KMS证书
    const CertInfos2* kmsCert = GetCachedCertificate();
    if (!kmsCert) {
        kmclog_e(LOG_TAG, "KMS certificate not found");
        return false;
    }
    
    uint64_t expectedPeriodNo = generateKeyPeriodNo(
        timestamp, 
        kmsCert->userKeyPeriod, 
        kmsCert->userKeyOffset
    );

    // 获取密钥材料
    KeyInfos2* keyMaterial = const_cast<KeyInfos2*>(GetCachedKey(user_uri, expectedPeriodNo));
    if (!keyMaterial) {
        kmclog_e(LOG_TAG, "Key material not found for period: %llu", expectedPeriodNo);
        return false;
    }

    out_key_info = *keyMaterial;
    return true;
}

bool CacheManager::UpdateGmkInternal(const GmkInfo& new_gmk_info) {
    const std::string& user_uri = new_gmk_info.userUri;
    const std::string& group_id = new_gmk_info.groupId;
    const std::string& gmk_id = new_gmk_info.gmkId;
    uint64_t new_db_id = new_gmk_info.id;
    
    std::string latest_key = GenerateUserGroupGmkPrefix(user_uri, group_id);
    auto latest_it = m_latestGmkDbIds.find(latest_key);
    
    if (latest_it == m_latestGmkDbIds.end()) {
        kmclog_i(LOG_TAG, "No cached GMK for user %s group %s, adding new GMK with db_id %llu", 
                 user_uri.c_str(), group_id.c_str(), new_db_id);
    } else {
        kmclog_i(LOG_TAG, "GMK update for user %s group %s: db_id %llu -> %llu", 
                 user_uri.c_str(), group_id.c_str(), latest_it->second, new_db_id);
    }
    
    // 更新缓存
    std::string cache_key = GenerateGmkMapKey(user_uri, group_id, gmk_id);
    m_cachedGmks[cache_key] = new_gmk_info;
    m_latestGmkDbIds[latest_key] = new_db_id;
    
    // 检查并清理超出限制的GMK
    CleanupOldGmks(user_uri);
    
    // 通知GMK更新
    NotifyDataUpdate(DataUpdateType::GMK_UPDATED, user_uri);
    
    kmclog_i(LOG_TAG, "GMK cache updated successfully - User: %s, Group: %s, ID: %s, DB_ID: %llu", 
             user_uri.c_str(), group_id.c_str(), gmk_id.c_str(), new_db_id);
    
    return true;
}

void CacheManager::CleanupOldGmks(const std::string& user_uri) {
    // 统计该用户的GMK总数
    std::vector<std::pair<std::string, GmkInfo*>> user_gmks;
    
    for (auto& pair : m_cachedGmks) {
        if (pair.second.userUri == user_uri) {
            user_gmks.emplace_back(pair.first, &pair.second);
        }
    }
    
    // 如果超过限制，按数据库ID排序并删除ID最小的
    if (user_gmks.size() > MAX_GMK_ENTRIES_PER_USER) {
        // 按GMK的数据库id字段排序（id越小越旧）
		std::sort(user_gmks.begin(), user_gmks.end(),
				  [](const std::pair<std::string, GmkInfo *> &a,
					 const std::pair<std::string, GmkInfo *> &b) {
					  return a.second->id < b.second->id;
				  });

		// 删除最旧的GMK，保持数量在限制内
        size_t to_remove = user_gmks.size() - MAX_GMK_ENTRIES_PER_USER;
        for (size_t i = 0; i < to_remove; ++i) {
            const std::string& cache_key = user_gmks[i].first;
            const GmkInfo* gmk_info = user_gmks[i].second;
            
            kmclog_i(LOG_TAG, "Cleaned up old GMK - User: %s, Group: %s, GMK_ID: %s, DB_ID: %llu", 
                     user_uri.c_str(), gmk_info->groupId.c_str(), gmk_info->gmkId.c_str(), gmk_info->id);
            
            m_cachedGmks.erase(cache_key);
            
            // 如果删除的是最新的GMK，需要更新最新GMK记录
            std::string latest_key = GenerateUserGroupGmkPrefix(gmk_info->userUri, gmk_info->groupId);
            auto latest_it = m_latestGmkDbIds.find(latest_key);
            if (latest_it != m_latestGmkDbIds.end() && latest_it->second == gmk_info->id) {
                m_latestGmkDbIds.erase(latest_it);
            }
            
            NotifyDataUpdate(DataUpdateType::GMK_DELETED, user_uri);
        }
    }
}

std::string CacheManager::GenerateGmkMapKey(const std::string& user_uri, const std::string& group_id, const std::string& gmk_id) const {
    return user_uri + ":" + group_id + ":" + gmk_id;
}

std::string CacheManager::GenerateUserGmkPrefix(const std::string& user_uri) const {
    return user_uri + ":";
}

std::string CacheManager::GenerateUserGroupGmkPrefix(const std::string& user_uri, const std::string& group_id) const {
    return user_uri + ":" + group_id;
}

GmkInfo* CacheManager::pickGmk(const std::string& userUri, const std::string& groupNumber, uint64_t timestamp) {
    std::vector<GmkInfo> cachedGmks = GetCachedGmks(userUri, groupNumber);
    if (!cachedGmks.empty()) {
        kmclog_d(LOG_TAG, "pickGmk, gmk cache size: %lu", cachedGmks.size());
        GmkInfo* nearest = getNearestGmk(cachedGmks, timestamp);
        if (nearest != nullptr) {
            kmclog_d(LOG_TAG, "pickGmk, pick nearest gmk success.");
            return nearest;
        } else {
            GmkInfo* latest = getLatestGmk(cachedGmks);
            if (latest != nullptr) {
                kmclog_d(LOG_TAG, "pickGmk, pick nearest gmk success.");
                return latest;
            }
        }
    }

    kmclog_e(LOG_TAG, "pickGmk, no gmk, return null");
    return nullptr;
}

GmkInfo* CacheManager::getNearestGmk(const std::vector<GmkInfo>& gmks, uint64_t timestamp) {
    GmkInfo* nearestGmk = nullptr;
    uint64_t interval = (1ULL << 64) - 1;
    int latestTag = 0;
    
    for (const GmkInfo& gmk : gmks) {
		int tag = strtol(gmk.eTag.c_str(), nullptr, 10);
		uint64_t activateTime = strtoull(gmk.activateTime.c_str(), nullptr, 10);

		if (timestamp > activateTime) {
            uint64_t intervalTemp = timestamp - activateTime;
            if (intervalTemp < interval) {
                nearestGmk = const_cast<GmkInfo*>(&gmk);
                interval = intervalTemp;
                latestTag = tag;
            } else if (intervalTemp == interval) {
                if (tag > latestTag) {
                    nearestGmk = const_cast<GmkInfo*>(&gmk);
                    latestTag = tag;
                }
            }
        }
    }
    
    if (nearestGmk != nullptr) {
        kmclog_d(LOG_TAG, "getNearestGmk, timestamp : %llu, nearestGmk : not null", timestamp);
    } else {
        kmclog_d(LOG_TAG, "etNearestGmk, timestamp : %llu, nearestGmk : null", timestamp);
    }
    
    return nearestGmk;
}

GmkInfo* CacheManager::getLatestGmk(const std::vector<GmkInfo>& gmks) {
    GmkInfo* latestGmk = nullptr;
    uint64_t latestActiveTime = 0;
    int latestTag = 0;
    
    for (const GmkInfo& gmk : gmks) {
        int tag = strtol(gmk.eTag.c_str(), nullptr, 10);
		uint64_t activateTime = strtoull(gmk.activateTime.c_str(), nullptr, 10);
        
        if (tag > latestTag || (tag == latestTag && activateTime > latestActiveTime)) {
            latestGmk = const_cast<GmkInfo*>(&gmk);
            latestTag = tag;
            latestActiveTime = activateTime;
        }
    }
    
    if (latestGmk == nullptr && !gmks.empty()) {
        latestGmk = const_cast<GmkInfo*>(&gmks[0]);
    }
    
    if (latestGmk != nullptr) {
        kmclog_d(LOG_TAG, "getLatestGmk, latestGmk : not null");
    } else {
        kmclog_d(LOG_TAG, "getLatestGmk, latestGmk : null");
    }
    
    return latestGmk;
}

std::vector<GmkInfo> CacheManager::GetCachedGmks(const std::string& user_uri) {
    {
        ReadLockGuard lock(m_rwLock);
        
        // 先从缓存中查找该用户的GMK记录
        std::vector<GmkInfo> result;
        for (const auto& pair : m_cachedGmks) {
            if (pair.second.userUri == user_uri) {
                result.push_back(pair.second);
            }
        }
        
        // 如果缓存中有数据，直接返回
        if (!result.empty()) {
            // 按数据库id排序
            std::sort(result.begin(), result.end(), 
                      [](const GmkInfo& a, const GmkInfo& b) {
                          return a.id < b.id;
                      });
            return result;
        }
    }
    
    // 缓存中没有数据，从数据库加载
    kmclog_i(LOG_TAG, "No GMK found in cache for user %s, loading from database", user_uri.c_str());
    
    SqliteDatabase database;
    if (!database.IsAvailable()) {
        kmclog_e(LOG_TAG, "Database is not available for GMK query");
        return std::vector<GmkInfo>();
    }
    
    std::vector<GmkInfo> db_gmks;
    if (!database.QueryGmkInfoByUser(user_uri, db_gmks)) {
        kmclog_e(LOG_TAG, "Failed to query GMK info from database for user: %s", user_uri.c_str());
        return std::vector<GmkInfo>();
    }
    
    if (db_gmks.empty()) {
        kmclog_i(LOG_TAG, "No GMK records found in database for user: %s", user_uri.c_str());
        return std::vector<GmkInfo>();
    }
    
    // 将数据库中的GMK记录加载到缓存
    {
        WriteLockGuard lock(m_rwLock);
        
        for (const GmkInfo& gmk_info : db_gmks) {
            const std::string& group_id = gmk_info.groupId;
            const std::string& gmk_id = gmk_info.gmkId;
            uint64_t db_id = gmk_info.id;
            
            // 添加到缓存
            std::string cache_key = GenerateGmkMapKey(user_uri, group_id, gmk_id);
            m_cachedGmks[cache_key] = gmk_info;
            
            // 更新最新GMK数据库ID
            std::string latest_key = GenerateUserGroupGmkPrefix(user_uri, group_id);
            auto latest_it = m_latestGmkDbIds.find(latest_key);
            if (latest_it == m_latestGmkDbIds.end() || db_id > latest_it->second) {
                m_latestGmkDbIds[latest_key] = db_id;
            }
        }
        
        // 检查并清理超出限制的GMK
        CleanupOldGmks(user_uri);
        
        kmclog_i(LOG_TAG, "Loaded %zu GMK records from database to cache for user: %s", 
                 db_gmks.size(), user_uri.c_str());
    }
    
    // 按数据库id排序后返回
    std::sort(db_gmks.begin(), db_gmks.end(), 
              [](const GmkInfo& a, const GmkInfo& b) {
                  return a.id < b.id;
              });
    
    return db_gmks;
}

std::vector<GmkInfo> CacheManager::GetCachedGmks(const std::string& user_uri, const std::string& group_id) {
    {
        ReadLockGuard lock(m_rwLock);
        
        // 先从缓存中查找该用户和组的GMK记录
        std::vector<GmkInfo> result;
        for (const auto& pair : m_cachedGmks) {
            if (pair.second.userUri == user_uri && pair.second.groupId == group_id) {
                result.push_back(pair.second);
            }
        }
        
        // 如果缓存中有数据，直接返回
        if (!result.empty()) {
            // 按数据库id排序
            std::sort(result.begin(), result.end(), 
                      [](const GmkInfo& a, const GmkInfo& b) {
                          return a.id < b.id;
                      });
            return result;
        }
    }
    
    // 缓存中没有数据，从数据库加载
    kmclog_i(LOG_TAG, "No GMK found in cache for user %s group %s, loading from database", 
             user_uri.c_str(), group_id.c_str());
    
    SqliteDatabase database;
    if (!database.IsAvailable()) {
        kmclog_e(LOG_TAG, "Database is not available for GMK query");
        return std::vector<GmkInfo>();
    }
    
    std::vector<GmkInfo> db_gmks;
    if (!database.QueryGmkInfo(user_uri, group_id, db_gmks)) {
        kmclog_e(LOG_TAG, "Failed to query GMK info from database for user: %s, group: %s", 
                 user_uri.c_str(), group_id.c_str());
        return std::vector<GmkInfo>();
    }
    
    if (db_gmks.empty()) {
        kmclog_i(LOG_TAG, "No GMK records found in database for user: %s, group: %s", 
                 user_uri.c_str(), group_id.c_str());
        return std::vector<GmkInfo>();
    }
    
    // 将数据库中的GMK记录加载到缓存
    {
        WriteLockGuard lock(m_rwLock);
        
        for (const GmkInfo& gmk_info : db_gmks) {
            const std::string& gmk_id = gmk_info.gmkId;
            uint64_t db_id = gmk_info.id;
            
            // 添加到缓存
            std::string cache_key = GenerateGmkMapKey(user_uri, group_id, gmk_id);
            m_cachedGmks[cache_key] = gmk_info;
            
            // 更新最新GMK数据库ID
            std::string latest_key = GenerateUserGroupGmkPrefix(user_uri, group_id);
            auto latest_it = m_latestGmkDbIds.find(latest_key);
            if (latest_it == m_latestGmkDbIds.end() || db_id > latest_it->second) {
                m_latestGmkDbIds[latest_key] = db_id;
            }
        }
        
        // 检查并清理超出限制的GMK
        CleanupOldGmks(user_uri);
        
        kmclog_i(LOG_TAG, "Loaded %zu GMK records from database to cache for user: %s, group: %s", 
                 db_gmks.size(), user_uri.c_str(), group_id.c_str());
    }
    
    // 按数据库id排序后返回
    std::sort(db_gmks.begin(), db_gmks.end(), 
              [](const GmkInfo& a, const GmkInfo& b) {
                  return a.id < b.id;
              });
    
    return db_gmks;
}

bool CacheManager::HasCachedGmk(const std::string& user_uri, const std::string& group_id, const std::string& gmk_id) const {
    ReadLockGuard lock(m_rwLock);
    
    std::string cache_key = GenerateGmkMapKey(user_uri, group_id, gmk_id);
    return m_cachedGmks.find(cache_key) != m_cachedGmks.end();
}

void CacheManager::ClearGmkCache(const std::string& user_uri, const std::string& group_id) {
    WriteLockGuard lock(m_rwLock);
    
    if (user_uri.empty()) {
        // 清空所有GMK缓存
        m_cachedGmks.clear();
        m_latestGmkDbIds.clear();
        kmclog_i(LOG_TAG, "All GMK caches cleared");
    } else if (group_id.empty()) {
        // 清空指定用户的所有GMK缓存
        std::vector<std::string> keys_to_remove;
        for (const auto& pair : m_cachedGmks) {
            if (pair.second.userUri == user_uri) {
                keys_to_remove.push_back(pair.first);
            }
        }
        
        for (const std::string& key : keys_to_remove) {
            m_cachedGmks.erase(key);
        }
        
        // 清理对应的最新GMK记录
        std::vector<std::string> latest_keys_to_remove;
        std::string user_prefix = GenerateUserGmkPrefix(user_uri);
        for (const auto& pair : m_latestGmkDbIds) {
            if (pair.first.substr(0, user_prefix.length()) == user_prefix) {
                latest_keys_to_remove.push_back(pair.first);
            }
        }
        
        for (const std::string& key : latest_keys_to_remove) {
            m_latestGmkDbIds.erase(key);
        }
        
        kmclog_i(LOG_TAG, "GMK cache cleared for user: %s", user_uri.c_str());
    } else {
        // 清空指定用户和组的GMK缓存
        std::vector<std::string> keys_to_remove;
        for (const auto& pair : m_cachedGmks) {
            if (pair.second.userUri == user_uri && pair.second.groupId == group_id) {
                keys_to_remove.push_back(pair.first);
            }
        }
        
        for (const std::string& key : keys_to_remove) {
            m_cachedGmks.erase(key);
        }
        
        // 清理对应的最新GMK记录
        std::string latest_key = GenerateUserGroupGmkPrefix(user_uri, group_id);
        m_latestGmkDbIds.erase(latest_key);
        
        kmclog_i(LOG_TAG, "GMK cache cleared for user: %s, group: %s", user_uri.c_str(), group_id.c_str());
    }
}

size_t CacheManager::GetGmkCacheSize() const {
    ReadLockGuard lock(m_rwLock);
    return m_cachedGmks.size();
}

size_t CacheManager::GetGmkCacheSize(const std::string& user_uri) const {
    ReadLockGuard lock(m_rwLock);
    
    size_t count = 0;
    for (const auto& pair : m_cachedGmks) {
        if (pair.second.userUri == user_uri) {
            count++;
        }
    }
    return count;
}

// 内部Holder管理方法
void CacheManager::UpdateKmsCertHolder() {
    if (m_hasCachedCert) {
        m_cachedKmsCertHolder = make_unique<KmsCertHolder>(m_cachedCertificate);
        kmclog_d(LOG_TAG, "Updated KmsCertHolder for certificate: %s", m_cachedCertificate.certUri.c_str());
    } else {
        m_cachedKmsCertHolder.reset();
        kmclog_d(LOG_TAG, "Cleared KmsCertHolder (no certificate)");
    }
}

void CacheManager::UpdateUserKeyMaterialHolder(const KeyInfos2& key_info) {
    std::string holder_key = GenerateUserKeyMaterialHolderKey(key_info);
    m_cachedUserKeyMaterialHolders[holder_key] = make_unique<UserKeyMaterialHolder>(key_info, m_cachedKmsCertHolder.get()->Get());
    kmclog_d(LOG_TAG, "Updated UserKeyMaterialHolder for user: %s, period: %llu", 
             key_info.userID.c_str(), key_info.keyPeriodNo);
}

void CacheManager::ClearAllUserKeyMaterialHolders(const std::string& user_uri) {
    if (user_uri.empty()) {
        // 清空所有
        size_t old_size = m_cachedUserKeyMaterialHolders.size();
        m_cachedUserKeyMaterialHolders.clear();
        kmclog_d(LOG_TAG, "Cleared all UserKeyMaterialHolders, removed %zu entries", old_size);
    } else {
        // 清空指定用户的（需要通过KeyInfos2的userID来匹配）
        std::vector<std::string> holders_to_remove;
        
        // 遍历现有的密钥缓存来找到对应的userID
        for (const auto& key_pair : m_cachedKeys) {
            if (key_pair.second.userUri == user_uri) {
                std::string holder_key = GenerateUserKeyMaterialHolderKey(key_pair.second);
                holders_to_remove.push_back(holder_key);
            }
        }
        
        for (const std::string& key : holders_to_remove) {
            m_cachedUserKeyMaterialHolders.erase(key);
        }
        
        kmclog_d(LOG_TAG, "Cleared UserKeyMaterialHolders for user: %s, removed %zu entries", 
                 user_uri.c_str(), holders_to_remove.size());
    }
}

std::string CacheManager::GenerateUserKeyMaterialHolderKey(const KeyInfos2& key_info) const {
    return key_info.userID + ":" + KmcUtils::uint64ToString(key_info.keyPeriodNo);
}

// Holder访问接口（供core调用）
KmsCertHolder* CacheManager::GetKmsCertHolder() const {
    ReadLockGuard lock(m_rwLock);
    return m_cachedKmsCertHolder.get();
}

UserKeyMaterialHolder* CacheManager::GetUserKeyMaterialHolder(const std::string& user_uri, uint64_t key_period_no) const {
    ReadLockGuard lock(m_rwLock);
    
    // 首先查找对应的密钥信息以获取userID
    std::string cache_key = GenerateKeyMapKey(user_uri, key_period_no);
    auto key_it = m_cachedKeys.find(cache_key);
    if (key_it == m_cachedKeys.end()) {
        return nullptr;
    }
    
    // 生成holder key并查找
    std::string holder_key = GenerateUserKeyMaterialHolderKey(key_it->second);
    auto holder_it = m_cachedUserKeyMaterialHolders.find(holder_key);
    if (holder_it != m_cachedUserKeyMaterialHolders.end()) {
        return holder_it->second.get();
    }
    
    return nullptr;
}

void CacheManager::PrintCacheStatistics() const {
    ReadLockGuard lock(m_rwLock);
    
    kmclog_i(LOG_TAG, "=== Cache Statistics ===");
    kmclog_i(LOG_TAG, "Certificate cache: %zu entries", GetCertificateCacheSize());
    kmclog_i(LOG_TAG, "Key cache: %zu entries", GetKeyCacheSize());
    kmclog_i(LOG_TAG, "GMK cache: %zu entries", GetGmkCacheSize());
    kmclog_i(LOG_TAG, "KmsCertHolder cache: %zu entries", m_cachedKmsCertHolder != nullptr ? 1 : 0);
    kmclog_i(LOG_TAG, "UserKeyMaterialHolder cache: %zu entries", m_cachedUserKeyMaterialHolders.size());
    kmclog_i(LOG_TAG, "Tracked users: %zu", m_latestKeyPeriods.size());
    kmclog_i(LOG_TAG, "Tracked user groups: %zu", m_latestGmkDbIds.size());
    kmclog_i(LOG_TAG, "Update callbacks: %zu", m_updateCallbacks.size());
    kmclog_i(LOG_TAG, "========================");
}

} // namespace KMC