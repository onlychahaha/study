#include "SessionManager.h"
#include "EncryptUtils.h"

#include <iostream>
#include <string>
#include "native-logic.h"
#include "native-eccsi-sakke-msg-builder.h"
//#include "ECCSI-SAKKE/4u2change/ue-group-keying-materials.h"

extern "C" {
    #include "utils/common-utils.h"
    #include "core/kmc-core.h"
    #include "open-source-module/base64.h"
    #include "stdio.h"
}

namespace KMC {



void custom_log(srtp_log_level_t level, const char *msg, void *data) {
    // 无需使用 data，直接忽略
    kmclog_d(LOG_TAG, msg);
}

/**
 * @brief 创建新的会话并返回会话标识符
 *
 * 根据不同的会话类型和作用域类型创建P2P或群组会话。该方法会执行参数合法性检查，
 * 并根据参数组合选择合适的会话创建逻辑。
 *
 * @param kmsUri KMS服务器的URI地址（必填）
 * @param userUri 当前用户的唯一标识URI（必填）
 * @param type 会话类型（如媒体传输、信令等）
 * @param scopeType 会话作用域类型（P2P或GROUP）
 * @param p2pInfo P2P会话的配置信息（当scopeType为P2P时必填）
 * @param groupInfo 群组会话的配置信息（当scopeType为GROUP时必填）
 * @param mikey 会话密钥信息（在接收端P2P会话创建时需要提供）
 * @param ssrc 同步源标识符（Session-Specific Conference Token）
 *
 * @return Result<int64_t>
 *   - 成功时：包含会话ID（>0）、成功状态(true)和空错误信息
 *   - 失败时：包含0作为ID、失败状态(false)和具体错误描述
 *
 * @note 参数要求：
 *   - kmsUri和userUri不能为空
 *   - P2P模式时：
 *     - 需提供p2pInfo
 *     - 发起方需提供空mikey，接收方需提供有效mikey
 *   - 群组模式时需提供有效的groupInfo
 *
 * @warning 调用前需确保：
 *   - 已通过setupKmcCore完成KMC核心初始化（由Java层保证）
 *   - 参数组合需与scopeType严格匹配
 */
Result<int64_t> SessionManager::createSession(const std::string kmsUri, const std::string userUri, SessionType type, ScopeType scopeType,
                                                         const std::shared_ptr<P2PInfo> p2pInfo, const std::shared_ptr<GroupInfo> groupInfo,
                                                         const std::string mikey, int ssrc) {
    // 参数合法性检查
    if (kmsUri.empty() || userUri.empty()) {
        kmclog_e(LOG_TAG, "createSession: Missing required parameters");
        return Result<int64_t>(0, false, "Missing required parameters");
    }

    if (type == SessionType::PTT || type == SessionType::VIDEO) {
        // 音视频业务时初始化srtp库
        if (!initSrtp()) {
            kmclog_e(LOG_TAG, "createSession: Failed to initialize SRTP");
            return Result<int64_t>(0, false, "Failed to initialize SRTP");
        }
    }

    if (scopeType == ScopeType::P2P && p2pInfo != nullptr && mikey.empty()
        && userUri == p2pInfo->initiatorUri) {
        // java 在调用createSession 之前先调用setupKmcCore
        kmclog_i(LOG_TAG, "createSession: P2P session to initiator");
        return createP2PSeesion(userUri, type, p2pInfo, ssrc);
    } else if (scopeType == ScopeType::P2P && !mikey.empty() && userUri == p2pInfo->receiverUri) {
        kmclog_i(LOG_TAG, "createSession: P2P session to receiver");
        return createP2PSeesionFromMikey(userUri, type, p2pInfo, mikey, ssrc);
    } else if (scopeType == ScopeType::GROUP && groupInfo != nullptr) {
        kmclog_i(LOG_TAG, "createSession: Group session");
        return createGroupSession(type, groupInfo, ssrc);
    } else {
        kmclog_e(LOG_TAG, "Invalid scopeType and p2pInfo/groupInfo combination");
        return Result<int64_t>(0, false, "Invalid scopeType and p2pInfo/groupInfo combination");
    }
}

/**
 * @brief 根据会话ID从缓存中获取MIKEY数据
 *
 * 通过会话ID构建缓存键，并从缓存中检索对应的MIKEY数据。该方法假设会话已存在且缓存有效。
 *
 * @param sessionId 要查询的会话唯一标识符
 *
 * @return Result<std::string>
 *   - 成功时：返回包含MIKEY字符串、成功状态(true)和空错误信息的Result对象
 *   - 失败时：返回空字符串、失败状态(false)和具体错误描述（取决于缓存实现）
 *
 * @note
 *   - 该函数依赖缓存中存在对应的会话数据
 *   - MIKEY数据可能为空（如会话未初始化或缓存未命中）
 *
 * @warning
 *   - 调用前需确保会话已通过createSession创建并存在于缓存中
 *   - 若会话不存在可能导致未定义行为（如空指针访问）
 */
Result<std::string> SessionManager::getMikey(int64_t sessionId) {
    std::string key = buildKey(sessionId);
    std::shared_ptr<SessionContext> context = m_cachePtr->get(key);

    if (!context) {
        return Result<std::string>("", false, "Session not found");
    }
    return Result<std::string>(context->mikey, true, "");
}

/**
 * @brief 生成新的P2P Mikey消息并返回Base64编码后的结果。
 *
 * 该函数根据给定的会话ID、KMS URI、用户URI和P2P信息生成P2P Mikey消息，
 * 并将其编码为Base64字符串返回。同时更新会话上下文中的相关信息。
 *
 * @param sessionId 会话ID，用于获取对应的会话上下文。
 * @param kmsUri 发起者的KMS URI（需已包含在p2pInfo的iKmsUri字段中）。
 * @param userUri 用户URI（需已包含在p2pInfo的initiatorUri字段中）。
 * @param p2pInfo P2P会话信息，包含接收方的KMS URI（rKmsUri）、用户URI（receiverUri）等。
 * @param mo 主叫
 * @param mt 被叫
 *
 * @return Result<std::string> 包含生成的Base64编码Mikey消息（成功）或错误信息（失败）。
 *
 * @pre 会话类型必须为PTT或VIDEO，且scopeType为P2P。
 * @note 如果会话类型或scopeType不符合要求，将返回错误结果。
 * @note 该函数会修改会话上下文中的p2pInfo和mikey字段。
 */
Result<std::string>
SessionManager::genNewMikey(int64_t						   sessionId,
							std::string					   kmsUri,
							std::string					   userUri,
							const std::shared_ptr<P2PInfo> p2pInfo,
							std::string					   mo,
							std::string					   mt)
{
	std::string key = buildKey(sessionId);
    std::shared_ptr<SessionContext> context = m_cachePtr->get(key);
    if (context->type != SessionType::PTT && context->type != SessionType::VIDEO ) {
        return Result<std::string>("", false, "Invalid session type");
    }
    if (context->scopeType != ScopeType::P2P) {
        return Result<std::string>("", false, "Invalid scope type");
    }

    time_t curtime;
    time(&curtime);
    uint8_t container[MAX_MESSAGE_LEN];
    size_t container_len = 0;
    context->p2pInfo = p2pInfo;

    CacheManager& cache = CacheManager::GetInstance();
    KeyInfos2 keyInfo;
    cache.PickupKeyMaterial(curtime, userUri, keyInfo);
    KmsCertHolder* kmsCertHolder = cache.GetKmsCertHolder();
    UserKeyMaterialHolder* userKeyHolder = cache.GetUserKeyMaterialHolder(userUri, keyInfo.keyPeriodNo);

    session_key_material_t key_context;

    uint8_t userDate = 0;
    // 生成P2P Mikey消息
    generateP2PMikeyMessage2(reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->iKmsUri.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->rKmsUri.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->initiatorUri.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->receiverUri.data())),
                             userKeyHolder->Get(), curtime, container, &container_len,
                             reinterpret_cast<uint8_t*>(const_cast<char*>(mo.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(mt.data())),
                             context->mikeySakkeMsg->hdr.csb_id_value.msg,
                             context->ptp_ssv, context->mikeySakkeMsg->rand.random_value.msg, &key_context,
                             kmsCertHolder->Get(), &userDate);
    context->mikeySakkeMsg = std::make_shared<mikey_sakke_msg_t>(key_context.mikey_sakke_msg);
    char container_base64[MAX_MESSAGE_LEN];
    base64_encode(container, container_len, container_base64);
    context->mikey = container_base64;

    // 衍生秘钥不变的话应该不用重新生成。

    return Result<std::string>(container_base64, true, "");
}
    void print_user_key_material(const user_key_material *material) {
        if (material == NULL) {
            printf("Error: material is NULL\n");
            return;
        }

        // 打印SSK
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("print_user_key_material", "SSK:", 8, material->SSK, material->SSK_len);

        // 打印RSK
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("print_user_key_material", "RSK:", 8, material->RSK, material->RSK_len);

        // 打印PVT
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("print_user_key_material", "PVT:", 8, material->PVT, material->PVT_len);

        // 打印HASH
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("print_user_key_material", "HASH:", 8, material->HASH, material->HASH_len);

        // 打印uid
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("print_user_key_material", "uid:", 8, material->uid, material->uid_len);
    }

/**
 * @brief 创建P2P会话
 *
 * 该函数用于创建一个点对点（P2P）会话，生成相关的会话密钥和上下文信息。
 *
 * @param userUri 用户的URI信息
 * @param type 会话类型，可以是普通P2P或GIS类型
 * @param p2pInfo 包含P2P会话相关信息的结构体指针
 * @param ssrc 会话同步源标识符
 *
 * @return Result<int64_t> 返回会话创建的结果，包含会话ID或错误信息
 *
 * @throws std::runtime_error 如果会话创建过程中出现错误，将抛出异常
 *
 * @note 该函数会生成随机数、创建会话密钥，并将相关信息保存到会话上下文中。
 *       会话类型为GIS时，会设置特定的标识位。
 */
Result<int64_t> SessionManager::createP2PSeesion(const std::string userUri,
                                                 SessionType type,
                                                 const std::shared_ptr<P2PInfo> p2pInfo,
                                                 int ssrc) {

    // 创建SessionContext
    std::shared_ptr<SessionContext> context = std::make_shared<SessionContext>();
    context->p2pInfo = p2pInfo;
    context->userType = UserType::SEND;
    context->type = type;
    //user_key_material userKeyMaterial = {0};
    time_t curtime;
    time(&curtime);

    kmclog_i(LOG_TAG, "generatePtpEssciAndSakkeMsg2 generate random ssv");
    uint8_t ssv[SSV_LEN] = {0};
    uint8_t pckId[PCK_ID_LEN] = {0};
    uint8_t rand[RANDOM_LEN] = {0};

    cu_obtainingRandomNumbers(ssv, SSV_LEN);
    cu_obtainingRandomNumbers(rand, RANDOM_LEN);
    cu_obtainingRandomNumbers(pckId, PCK_ID_LEN);
    pckId[0] &= 0x0F;  // 清除高四位（高4位=0000，低4位保留）
    if (type == SessionType::GIS) {
        pckId[0] |= 0x20;  // 设置高四位为 0010（0x20 = 0010 0000）
    } else {
        pckId[0] |= 0x10;  // 设置高四位为 0001
    }

    uint8_t container[MAX_MESSAGE_LEN];
    size_t container_len = 0;

    CacheManager& cache = CacheManager::GetInstance();
    KeyInfos2 keyInfo;
    cache.PickupKeyMaterial(curtime, userUri, keyInfo);
    KmsCertHolder* kmsCertHolder = cache.GetKmsCertHolder();
    UserKeyMaterialHolder* userKeyHolder = cache.GetUserKeyMaterialHolder(userUri, keyInfo.keyPeriodNo);

    print_user_key_material(userKeyHolder->Get());
    session_key_material_t key_context;
    uint8_t userDate = 0;
    // 生成P2P Mikey消息
    generateP2PMikeyMessage2(kmsCertHolder->Get()->KmsCertUri,
                             kmsCertHolder->Get()->KmsCertUri,
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->initiatorUri.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->receiverUri.data())),
                             userKeyHolder->Get(), curtime, container, &container_len,
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->initiatorUri.data())),
                             reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->receiverUri.data())),
                             pckId, ssv, rand, &key_context, kmsCertHolder->Get(), &userDate);

	context->mikeySakkeMsg = std::make_shared<mikey_sakke_msg_t>(key_context.mikey_sakke_msg);
    char container_base64[MAX_MESSAGE_LEN];
    base64_encode(container, container_len, container_base64);
    context->mikey = container_base64;
    memcpy(context->ptp_ssv, ssv, SSV_LEN);

    kmclog_i(LOG_TAG, "mikeyContainer(base64:): [%s]\n", context->mikey.data());

	genP2pSessionKey(type, context, p2pInfo, ssrc, &key_context);

    return saveContext(context);
}

/**
 * @brief 释放指定会话
 * @param userUri 用户的URI
 * @param sessionId 要释放的会话ID
 * @return Result<std::string> 包含操作结果的状态和消息。成功时返回状态为true，消息为空；失败时返回状态为false，并携带相应的错误信息。
 * @throws 如果sessionId为0，返回错误信息“Missing session ID”。
 * @throws 如果会话不存在，返回错误信息“Session not found”。
 */
Result<std::string> SessionManager::releaseSession(const std::string& userUri, int64_t sessionId) {
    if (sessionId == 0) {
        return Result<std::string>("", false, "Missing session ID");
    }

    std::string key = buildKey(sessionId);

    std::shared_ptr<SessionContext> context = m_cachePtr->get(key);
    if (!context) {
        return Result<std::string>("", false, "Session not found");
    }
    if (context->type == SessionType::PTT || context->type == SessionType::VIDEO) {
        releaseSrtpSeesion(context->enSession);
        releaseSrtpSeesion(context->deSession);
    }
    m_cachePtr->del(key);

    return Result<std::string>("", true, "");
}

Result<bool> SessionManager::clearSession() {
    if (m_cachePtr)
    {
        m_cachePtr->clear();
        return Result<bool>(true, true, "");
    }
    return Result<bool>(false, false, "Cache not initialized");
}

void SessionManager::releaseSrtpSeesion(srtp_t session) {
    if (session) {
        return;
    }
    void *p = srtp_get_user_data(session);
    destroy_user_data(p);
    srtp_set_user_data(session, NULL);
    srtp_dealloc(session);
}

void SessionManager::setupKmcCore(const std::string& userUri, CertInfos kmsCertInfo,
                                  KeyInfos keyInfo, /*uint8_t * curCommunity,*/ 
                                  user_key_material *userMaterial,
                                  kms_cert *kmsCert) {
    setupKmsCert(reinterpret_cast<uint8_t*>(kmsCertInfo.certUri),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.kmsUri),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.pubAuthKey),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.pubEncKey),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.validFrom),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.validTo),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.userKeyPeriod),
                 reinterpret_cast<uint8_t*>(kmsCertInfo.userKeyOffset),
                 kmsCert);

    char keyPeriodNoTem[12] = {0};
    sprintf(keyPeriodNoTem, "%d", keyInfo.keyPeriodNo);
    setupUserKeyMaterial(reinterpret_cast<uint8_t*>(kmsCertInfo.certUri),
                         reinterpret_cast<uint8_t*>(keyInfo.validFrom),
                         reinterpret_cast<uint8_t*>(keyInfo.userID),
                         reinterpret_cast<uint8_t*>(keyInfo.ssk),
                         reinterpret_cast<uint8_t*>(keyInfo.rsk),
                         reinterpret_cast<uint8_t*>(keyInfo.pvt),
                         reinterpret_cast<uint8_t*>(keyPeriodNoTem),
                         userMaterial, kmsCert);

}

Result<int64_t>
SessionManager::createGroupSession(SessionType type, const std::shared_ptr<GroupInfo> groupInfo, int ssrc) {

    std::shared_ptr<SessionContext> context = std::make_shared<SessionContext>();
    context->groupInfo = groupInfo;
    context->type = type;

    CacheManager& cache_mgr = CacheManager::GetInstance();
    GmkInfo *gmk = cache_mgr.pickGmk(groupInfo->userUri, groupInfo->groupID,
										 KmcUtils::getUnixTimestampSeconds());
    grp_keying_materials_t grpKeyingMaterials;
    KmcUtils::ConvertGmkToGroupMaterials(*gmk, &grpKeyingMaterials);
    mcdata_session_key_t mcdata_session_key;
    context->groupKeyingMaterials = std::make_shared<grp_keying_materials_t>(grpKeyingMaterials);

    if (type == SessionType::DATA) {
        // 生成数据业务的组呼衍生秘钥
        generateMcdataGrpSessionKey(reinterpret_cast<uint8_t*>(const_cast<char*>(groupInfo->groupID.data())), &mcdata_session_key, &grpKeyingMaterials);
        context->dataSessionKey = std::make_shared<mcdata_session_key_t>(mcdata_session_key);
    } else if (type == SessionType::GIS) {
        kmclog_e(LOG_TAG, "createGroupSession GIS not support");
    } else {
        // 生成音视频的组呼衍生秘钥
        context->grpSessionKey = std::make_shared<grp_session_key_t>();
        generateMcpttGrpSessionKeySync(&grpKeyingMaterials, context->grpSessionKey.get());
        creatP2GSrtpSession(context, ssrc, true, type);
        creatP2GSrtpSession(context, ssrc, false, type);
    }

    return saveContext(context);
}

Result<int64_t>
SessionManager::createP2PSeesionFromMikey(const std::string userUri, SessionType type,
                                          const std::shared_ptr<P2PInfo> p2pInfo,
                                          const std::string mikey, int ssrc) {
    // 创建SessionContext
    std::shared_ptr<SessionContext> context = std::make_shared<SessionContext>();
    context->p2pInfo = p2pInfo;
    context->type = type;
    context->mikey = mikey;

    uint8_t container_c[MAX_MESSAGE_LEN] = {0}; // 存放base64解码后的mikey message
    size_t container_len = cu_decodeBase64(mikey.data(), mikey.length(), container_c);


    size_t msg_len_without_sign = 0;

    /** 1、从container中解析获得相关参数信息 **/
    mikey_sakke_msg_t extracted_msg = extractEccsiSakkeMsgWithoutVerificationDecryption(
            container_c, container_len, &msg_len_without_sign);

    uint32_t ntp = cu_convertFromBytesToInt(extracted_msg.t.ts_value.msg, sizeof(extracted_msg.t.ts_value.msg));
    uint32_t time00_70 = 2208988800;
    time_t now = ntp - time00_70;

    CacheManager& cache = CacheManager::GetInstance();
    KeyInfos2 keyInfo;
    cache.PickupKeyMaterial(now, userUri, keyInfo);
    KmsCertHolder* kmsCertHolder = cache.GetKmsCertHolder();
    UserKeyMaterialHolder* userKeyHolder = cache.GetUserKeyMaterialHolder(userUri, keyInfo.keyPeriodNo);

    print_user_key_material(userKeyHolder->Get());
    session_key_material_t key_context;
    uint8_t userDate = 0;

    int ret = extractPtpEccsiSakkeMsg(kmsCertHolder->Get()->KmsCertUri,
                                      reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->initiatorUri.data())),
                                      reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->receiverUri.data())),
                                      container_c, container_len, nullptr, 0, &key_context, kmsCertHolder->Get(),
                                      userKeyHolder->Get(), &userDate);
    if (ret != 0) {
        kmclog_e(LOG_TAG, "extractPtpEccsiSakkeMsg failed, ret=%d", ret);
        return Result<int64_t>(0, false, "Failed to extract Mikey message");
    }
    if (memcmp(userUri.data(), key_context.mikey_sakke_msg.idr[1].id_value.msg, key_context.mikey_sakke_msg.idr[1].id_value.len) == 0) {
        kmclog_i(LOG_TAG, "extractPtpEccsiSakkeMsg callee");
        context->userType = UserType::RECEIVE;
    } else if (memcmp(userUri.data(), key_context.mikey_sakke_msg.idr[0].id_value.msg, key_context.mikey_sakke_msg.idr[0].id_value.len) == 0) {
        kmclog_i(LOG_TAG, "extractPtpEccsiSakkeMsg caller");
        context->userType = UserType::SEND;
    } else {
        kmclog_e(LOG_TAG, "extractPtpEccsiSakkeMsg failed, userUri not match");
        return Result<int64_t>(0, false, "Failed to extract Mikey message");
    }
    context->mikeySakkeMsg = std::make_shared<mikey_sakke_msg_t>(key_context.mikey_sakke_msg);

    memcpy(context->ptp_ssv, key_context.ssv, SSV_LEN);
    genP2pSessionKey(type, context, p2pInfo, ssrc, &key_context);
    return saveContext(context);
}

bool SessionManager::genP2pSessionKey(SessionType type, std::shared_ptr<SessionContext> context,
        const std::shared_ptr<P2PInfo> p2pInfo, int ssrc, session_key_material_t *key_context) {
    if (type == SessionType::DATA) {
        generateMcdataPtpSessionKey(key_context);
        context->dataSessionKey = std::make_shared<mcdata_session_key_t>(key_context->mcdata_session_key);
    } else if (type == SessionType::GIS) {
        context->gisCskId = std::make_shared<info_t>();
        context->gisCskId->len = key_context->mikey_sakke_msg.hdr.csb_id_value.len;
        memcpy(context->gisCskId->msg, key_context->mikey_sakke_msg.hdr.csb_id_value.msg, key_context->mikey_sakke_msg.hdr.csb_id_value.len);

        context->gisSessionKeyI = std::make_shared<info_t>();
        getGisDpck(reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->initiatorUri.data())),
                   p2pInfo->initiatorUri.length(),
                   key_context->ssv, SSV_LEN,
                   key_context->mikey_sakke_msg.hdr.csb_id_value.msg,
                   key_context->mikey_sakke_msg.hdr.csb_id_value.len,
                   context->gisSessionKeyI->msg,
                   &(context->gisSessionKeyI->len));

        context->gisSessionKeyR = std::make_shared<info_t>();
        getGisDpck(reinterpret_cast<uint8_t*>(const_cast<char*>(p2pInfo->receiverUri.data())),
                   p2pInfo->receiverUri.length(),
                   key_context->ssv, SSV_LEN,
                   key_context->mikey_sakke_msg.hdr.csb_id_value.msg,
                   key_context->mikey_sakke_msg.hdr.csb_id_value.len,
                   context->gisSessionKeyR->msg,
                   &(context->gisSessionKeyR->len));

        // TODO 调试打印，证书版本需要删除
        int base64_length = ((SSV_LEN + 12 + 2)/3) * 4;
        std::vector<char> container_base64(base64_length);
        base64_encode(key_context->ssv, SSV_LEN, &container_base64[0]);
        kmclog_i(LOG_TAG, "ssv(base64:): [%s]\n", container_base64.data());
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("genP2pSessionKey", "gisSessionKeyI:", 8, context->gisSessionKeyI->msg, context->gisSessionKeyI->len);
        E2E_INFO_PRINT_FORMATTED_OCTET_STRING("genP2pSessionKey", "gisSessionKeyR:", 8, context->gisSessionKeyR->msg, context->gisSessionKeyR->len);

        base64_length = ((key_context->mikey_sakke_msg.hdr.csb_id_value.len + 12 + 2)/3) * 4;
        container_base64.clear();
        container_base64.resize(base64_length);
        base64_encode(key_context->mikey_sakke_msg.hdr.csb_id_value.msg, key_context->mikey_sakke_msg.hdr.csb_id_value.len, &container_base64[0]);
        kmclog_i(LOG_TAG, "dpkpid(base64:): [%s]\n", container_base64.data());


    } else {
        generateMcpttP2pSessionKey(key_context);
        context->p2pSessionKey = std::make_shared<p2p_session_key_t>(key_context-> mcptt_ptp_session_key);
        creatP2PSrtpSession(context, ssrc, true, type);
        creatP2PSrtpSession(context, ssrc, false, type);
        kmclog_i(LOG_TAG, "genP2pSessionKey, enSession:%p", context->enSession);
        kmclog_i(LOG_TAG, "genP2pSessionKey, deSession:%p", context->deSession);
    }
    return true;
}

Result<int64_t> SessionManager::saveContext(std::shared_ptr<SessionContext> context) {
    // 生成唯一的sessionId
    int64_t sessionId = ++m_currentSessionId;

    context->sessionId = sessionId;
    // 生成唯一的key（这里使用sessionId作为key）
    std::string key = buildKey(sessionId);

    // 将SessionContext存入FixedCache
    if (!m_cachePtr->put(key, context)) {
        return Result<int64_t>(0, false, "Failed to store session in m_cachePtr");
    }

    return Result<int64_t>(sessionId, true, "");
}

std::shared_ptr<SessionContext> SessionManager::getContext(int64_t sessionId) {
    return m_cachePtr->get(buildKey(sessionId));
}

std::string SessionManager::buildKey(int64_t sessionId) {
    std::ostringstream keyStream;
    keyStream << sessionId;
    return keyStream.str();
}

// 初始化点呼SRTP会话
bool SessionManager::creatP2PSrtpSession(std::shared_ptr<SessionContext> context, int ssrcv, bool encrypt, SessionType type)
{
    srtp_ssrc_t ssrc;
    ssrc.type = ssrc_specific;
    ssrc.value = ssrcv;

    uint8_t key[2048] = {0};
    size_t key_len = 0;
    //uint8_t constant_value[] = {0x2A, 0xD0, 0x1C, 0x64};
    int csid;
    uint8_t salt[2048] = {0};
    size_t salt_len = 0;
    //uint8_t salt_constant[] = {0x39, 0xA2, 0xC1, 0x4B};
    // 用于发送方加密或者接收方解密
    if(((context->userType == UserType::SEND && encrypt) || (context->userType == UserType::RECEIVE && !encrypt)) && type == SessionType::PTT) {
        csid = CONST_CS_ID_MCPTT_DATA_FROM_INITIATOR;
        key_len =  context->p2pSessionKey->key_for_audio_data_from_initiator_value.len;
        memcpy(key, context->p2pSessionKey->key_for_audio_data_from_initiator_value.msg, key_len);
        salt_len = context->p2pSessionKey->salt_for_audio_data_from_initiator_value.len;
        memcpy(salt, context->p2pSessionKey->salt_for_audio_data_from_initiator_value.msg, salt_len);
    // 用于发送方解密或者接收方加密
    } else if(((context->userType == UserType::SEND && !encrypt) || (context->userType == UserType::RECEIVE && encrypt)) && type == SessionType::PTT) {
        csid = CONST_CS_ID_MCPTT_DATA_FROM_RECEIVER;
        key_len =  context->p2pSessionKey->key_for_audio_data_from_reveiver_value.len;
        memcpy(key, context->p2pSessionKey->key_for_audio_data_from_reveiver_value.msg, key_len);
        salt_len = context->p2pSessionKey->salt_for_audio_data_from_reveiver_value.len;
        memcpy(salt, context->p2pSessionKey->salt_for_audio_data_from_reveiver_value.msg, salt_len);
    } else if(((context->userType == UserType::SEND && encrypt) || (context->userType == UserType::RECEIVE && !encrypt)) && type == SessionType::VIDEO) {
        csid = CONST_CS_ID_MCVIDEO_DATA_FROM_INITIATOR;
        key_len =  context->p2pSessionKey->key_for_video_data_from_initiator_value.len;
        memcpy(key, context->p2pSessionKey->key_for_video_data_from_initiator_value.msg, key_len);
        salt_len = context->p2pSessionKey->salt_for_video_data_from_initiator_value.len;
        memcpy(salt, context->p2pSessionKey->salt_for_video_data_from_initiator_value.msg, salt_len);
    } else if(((context->userType == UserType::SEND && !encrypt) || (context->userType == UserType::RECEIVE && encrypt)) && type == SessionType::VIDEO) {
        csid = CONST_CS_ID_MCVIDEO_DATA_FROM_RECEIVER;
        key_len =  context->p2pSessionKey->key_for_video_data_from_reveiver_value.len;
        memcpy(key, context->p2pSessionKey->key_for_video_data_from_reveiver_value.msg, key_len);
        salt_len = context->p2pSessionKey->salt_for_video_data_from_reveiver_value.len;
        memcpy(salt, context->p2pSessionKey->salt_for_video_data_from_reveiver_value.msg, salt_len);
    }

    mki_pair_t *pair = create_pair();
    if (!pair) {
        return false;
    }

    int ret = initPilicy(csid, KmcContextManager::getInstance().getKmcAesAlgorithm(), key, key_len, salt, salt_len, &pair->mp_policy, ssrc);
    kmclog_i(LOG_TAG, "creatP2PSrtpSession, initPilicy ret = %d. crypto_policy = %d, csid = %d, key_len = %d, encrypt=%d",
             ret, KmcContextManager::getInstance().getKmcAesAlgorithm(), csid, key_len, encrypt);

    if (ret < 0) {
        destroy_pair(pair);
        free(pair);
        kmclog_e(LOG_TAG, "creatP2PSrtpSession, initPilicy failed");
        return false;
    }

    kmclog_i(LOG_TAG, "policy.rtp.cipher_type = %d", pair->mp_policy.rtp.cipher_type);
    kmclog_i(LOG_TAG, "policy.rtp.cipher_key_len = %d", pair->mp_policy.rtp.cipher_key_len);
    kmclog_i(LOG_TAG, "policy.key = %p", (void*)pair->mp_policy.key); // 确保不是 NULL
    // TODO 非脱敏日志，调试用，需要在正式版本删除
    E2E_INFO_PRINT_FORMATTED_OCTET_STRING("creatP2PSrtpSession", "key:", 8, key, key_len);
    E2E_INFO_PRINT_FORMATTED_OCTET_STRING("creatP2PSrtpSession", "salt:", 8, salt, salt_len);

    srtp_err_status_t err = srtp_create(encrypt? &context->enSession:&context->deSession, &pair->mp_policy);
    if (err != srtp_err_status_ok) {
        destroy_pair(pair);
        free(pair);
        kmclog_e(LOG_TAG, "creatP2PSrtpSession, srtp_create failed. status:[%d]", err);
        return false;
    }

    pair->mp_mki = buf_to_mki(context->mikeySakkeMsg->hdr.csb_id_value.msg, 4);
    if (KmcContextManager::getInstance().getKmcAesAlgorithm() ==  KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM) {
        pair->mp_keylen = 44;
    } else {
        pair->mp_keylen = 28;
    }

    void *user_data = create_session_user_data(context->mikeySakkeMsg->hdr.csb_id_value.msg,
                                               4, KmcContextManager::getInstance().getKmcAesAlgorithm(), csid, 0, ssrc);
    srtp_set_user_data(encrypt? context->enSession:context->deSession, user_data);
    pair->mp_mki = buf_to_mki(context->mikeySakkeMsg->hdr.csb_id_value.msg, 4);
    pair->mp_keylen = 4;
    add_pair_to_user_data(user_data, pair);

    return true;
}

bool SessionManager::initSrtp() {
    if (!KmcContextManager::getInstance().GetInitSrtp()) {
        srtp_install_log_handler(custom_log, NULL);
        srtp_err_status_t err = srtp_init();
        if (err != srtp_err_status_ok) {
            kmclog_e(LOG_TAG, "initSrtp, srtp_init failed. status:[%d]", err);
            return false;
        }
        KmcContextManager::getInstance().SetInitSrtp(true);
        kmclog_i(LOG_TAG, "initSrtp, srtp_init success");
    }
    return true;
}

// 初始化组呼SRTP会话
bool SessionManager::creatP2GSrtpSession(std::shared_ptr<SessionContext> context, int ssrcv, bool encrypt, SessionType type)
{
    kmclog_i(LOG_TAG, "creatP2GSrtpSession start");
    srtp_ssrc_t ssrc;
    ssrc.type = ssrc_specific;
    ssrc.value = ssrcv;
    // 根据PCK信息生成衍生密钥
    uint8_t key[2048] = {0};
    size_t key_len = 0;
    int csId;
    uint8_t salt[2048] = {0};
    size_t salt_len = 0;

    if(type == SessionType::PTT) {
        csId = CONST_CS_ID_MCPTT_GROUP;
        key_len =  context->grpSessionKey->audio_key_value.len;
        memcpy(key, context->grpSessionKey->audio_key_value.msg, key_len);
        salt_len =  context->grpSessionKey->audio_salt_value.len;
        memcpy(salt, context->grpSessionKey->audio_salt_value.msg, salt_len);
    } else {
        csId = CONST_CS_ID_MCVIDEO_GROUP;
        key_len =  context->grpSessionKey->video_key_value.len;
        memcpy(key, context->grpSessionKey->video_key_value.msg, key_len);
        salt_len =  context->grpSessionKey->video_salt_value.len;
        memcpy(salt, context->grpSessionKey->video_salt_value.msg, salt_len);
    }
    mki_pair_t *pair = create_pair();
    if (!pair) {
        return false;
    }
    int ret = initPilicy(csId, KmcContextManager::getInstance().getKmcAesAlgorithm(), key, key_len, salt, salt_len, &pair->mp_policy, ssrc);
    if (ret < 0) {
        destroy_pair(pair);
        free(pair);
        kmclog_e(LOG_TAG, "creatP2GSrtpSession, initPilicy failed");
        return false;
    }
    srtp_t &srtpCtx = encrypt? context->enSession:context->deSession;
    srtp_err_status_t err = srtp_create(&srtpCtx, &pair->mp_policy);
    if (err != srtp_err_status_ok) {
        destroy_pair(pair);
        free(pair);
        kmclog_e(LOG_TAG, "creatP2GSrtpSession, srtp_create failed");

        return false;
    }
    uint8_t keyId[8];
    memcpy(keyId, context->groupKeyingMaterials->gmk_id, 4);
    memcpy(keyId + 4, context->groupKeyingMaterials->guk_id, 4);

    void *user_data = create_session_user_data(keyId, 8, KmcContextManager::getInstance().getKmcAesAlgorithm(), csId, 1, ssrc);
    srtp_set_user_data(srtpCtx, user_data);
    pair->mp_mki = buf_to_mki(keyId, 8);
    if (KmcContextManager::getInstance().getKmcAesAlgorithm() == KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM) {
        pair->mp_keylen = 44;
    } else {
        pair->mp_keylen = 28;
    }
    add_pair_to_user_data(user_data, pair);
    return true;
}

int SessionManager::initPilicy(int csid, enum KMC_AES_ALGORITHM algorithm, uint8_t *key, int key_len, uint8_t *salt, int sale_len,
               srtp_policy_t *policy, srtp_ssrc_t ssrc)
{

    if (csid < 0 || algorithm < 0 || !key || !policy || !key_len) {
        return KMCSDK_FAIL;
    }
    if (algorithm == KMC_AES_ALGORITHM::ALGORITHM_AES_128_GCM) {
        kmclog_i(LOG_TAG, "initPilicy, algorithm = ALGORITHM_AES_128_GCM");
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy->rtp);
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy->rtcp);
    } else if (algorithm == KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM) {
        kmclog_i(LOG_TAG, "initPilicy, algorithm = ALGORITHM_AES_256_GCM");
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&policy->rtp);
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&policy->rtcp);
    }

    policy->ssrc = ssrc;
    policy->key = (uint8_t *)malloc(ENCRYPT_KEY_LEN);
    memset(policy->key, 0, ENCRYPT_KEY_LEN);
    if (algorithm == KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM) {
        memcpy(policy->key, key, key_len);
        memcpy(policy->key + key_len, salt, sale_len);
    } else {
        memcpy(policy->key, key, 16);
        memcpy(policy->key + 16, salt, 12);
    }

    policy->deprecated_ekt = NULL;
    policy->window_size = 128;
    policy->allow_repeat_tx = 0;
    policy->next = NULL;
    return KMCSDK_SUCCESS;
}


} //KMC