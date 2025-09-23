#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <atomic>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>

#include <srtp2/srtp.h>

#include "FixedCache.h"
#include "KmcContextManager.h"
#include "CacheManager.h"
#include "KmcUtils.h"

namespace KMC {

#define AES_GCM_TAG_LEN 16
#define ENCRYPT_KEY_LEN 2048


class FixedCache;
class SessionManager : public std::enable_shared_from_this<SessionManager> {
public:
    typedef std::shared_ptr<SessionManager> ptr;
    explicit SessionManager(FixedCache::ptr cachePtr = nullptr)
        : m_cachePtr(std::move(cachePtr)) {};

    ~SessionManager()
    {
        if (m_cachePtr) {
            clearSession(); 
            m_cachePtr.reset();
            m_cachePtr = nullptr;
        }
    }

    Result<int64_t> createSession(const std::string kmsUri, const std::string userUri, SessionType type, ScopeType scopeType,
                                  const std::shared_ptr<P2PInfo> p2pInfo, const std::shared_ptr<GroupInfo> groupInfo,
                                  const std::string mikey, int ssrc);

    Result<std::string> releaseSession(const std::string& userUri, int64_t sessionId);

    Result<std::string> getMikey(int64_t sessionId);

    std::shared_ptr<SessionContext> getContext(int64_t sessionId);

    int initPilicy(int csid, KMC_AES_ALGORITHM algorithm, uint8_t *key, int key_len, uint8_t *salt,
                   int sale_len, srtp_policy_t *policy, srtp_ssrc_t ssrc);

    Result<bool> clearSession();

	Result<std::string> genNewMikey(int64_t						   sessionId,
									std::string					   kmsUri,
									std::string					   userUri,
									const std::shared_ptr<P2PInfo> p2pInfo,
									std::string					   mo,
									std::string					   mt);

private:
    Result<int64_t> createP2PSeesion(const std::string userUri, SessionType type,
                                     const std::shared_ptr<P2PInfo> p2pInfo, int ssrc);
    Result<int64_t>
    createGroupSession(SessionType type,
                       const std::shared_ptr<GroupInfo> sharedPtr, int ssrc);
    Result<int64_t>
    createP2PSeesionFromMikey(const std::string userUri, SessionType type,
                              const std::shared_ptr<P2PInfo> p2pInfo,
                              const std::string mikey, int ssrc);
    void setupKmcCore(const std::string &userUri, CertInfos kmsCertInfo, KeyInfos keyInfo,
                      user_key_material *userMaterial, kms_cert *kmsCert);
    Result<int64_t> saveContext(std::shared_ptr<SessionContext> context);
    std::string buildKey(int64_t sessionId);
    std::string buildKey(const std::string userUri, const int keyPeriodNo);
    bool genP2pSessionKey(SessionType type, std::shared_ptr<SessionContext> context,
                          const std::shared_ptr<P2PInfo> p2pInfo, int ssrc, session_key_material_t *key_context);
    bool creatP2PSrtpSession(std::shared_ptr<SessionContext> context, int ssrcv, bool encrypt,
                             SessionType type);
    bool creatP2GSrtpSession(std::shared_ptr<SessionContext> context, int ssrcv, bool encrypt,
                             SessionType type);
    void releaseSrtpSeesion(srtp_t session);
    bool initSrtp();

public:
    // std::mutex m_sessionIdMutex;
    std::atomic<int64_t> m_currentSessionId{0};
    FixedCache::ptr m_cachePtr = nullptr;
};


} //KMC

#endif // SESSION_MANAGER_H