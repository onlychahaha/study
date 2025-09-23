//
// Created by zWX1124406 on 2025/3/20.
//
#include "EncryptSvc.h"

#include <iostream>
#include <sstream>
#include <string>

#include "EncryptUtils.h"

extern "C" {
#include "utils/common-utils.h"
#include "core/kmc-core.h"
#include "open-source-module/base64.h"
#include "stdio.h"
#include "native-eccsi-sakke-msg-builder.h"
}
#ifdef _WIN32  // Windows 平台
#include <winsock2.h>
#else  // Linux/UNIX 平台
#include <arpa/inet.h>  // 提供字节序转换函数（ntohl, htonl 等）
#include <securec.h>
#endif

namespace KMC {


Result<EncryptDataStruct> EncryptSvc::encryptData(unsigned char *data, int len, uint64_t sessionId, unsigned char *iv) {
    kmclog_i(LOG_TAG, "encryptData");
    // 获取加密算法
    EncryptDataStruct encryptData;
    std::shared_ptr<SessionContext> sessionContext = m_sessionManager->getContext(sessionId);
    if (sessionContext->type == SessionType::DATA) {
        if (iv == nullptr) {
            kmclog_i(LOG_TAG, "encryptData, iv is null");
            encryptData.data = encrypt(data, len, KmcContextManager::getInstance().getKmcAesAlgorithm(), sessionContext->dataSessionKey->dpck.msg);
        } else {
            kmclog_i(LOG_TAG, "encryptData, iv is not null");
            encryptData.data = encryptWithIv(data, len, KmcContextManager::getInstance().getKmcAesAlgorithm(), sessionContext->dataSessionKey->dpck.msg, iv);
        }
        encryptData.algorithm = KmcContextManager::getInstance().getKmcAesAlgorithm();

        std::vector<unsigned char> container(sessionContext->dataSessionKey->dppk_id.len);
        memcpy(&container[0], sessionContext->dataSessionKey->dppk_id.msg, sessionContext->dataSessionKey->dppk_id.len);
        encryptData.dppkid = container;
    } else if (sessionContext->type == SessionType::GIS) {
        std::shared_ptr<info_t> keyPtr = sessionContext->gisSessionKeyI;
        if (sessionContext->userType == UserType::RECEIVE) {
            keyPtr = sessionContext->gisSessionKeyR;
        }
        if (iv == nullptr) {
            encryptData.data = encrypt(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, keyPtr->msg);
        } else {
            encryptData.data = encryptWithIv(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, keyPtr->msg, iv);
        }
        encryptData.dppkid.resize(sessionContext->gisCskId->len);
        memcpy(encryptData.dppkid.data(), sessionContext->gisCskId->msg, sessionContext->gisCskId->len);
    }

    return Result<EncryptDataStruct>(encryptData, true,"");
}

std::vector<unsigned char> EncryptSvc::encrypt(unsigned char *data, int len, enum KMC_AES_ALGORITHM algorithm, unsigned char *key) {
    EncryptDataStruct encryptData;
    unsigned char iv[12] = {0};
    cu_obtainingRandomNumbers(iv,KMC_IV_LEN);

    std::vector<unsigned char> result(len + 16);
    int result_len = AES_gcm_encrypt(algorithm,
                                     data,
                                     len , NULL, 0,
                                     key, iv, KMC_IV_LEN, result.data());

    kmclog_i(LOG_TAG, "encryptData, after encrypt, length is %d", result_len);

    if (result_len < 0) {
        kmclog_e(TAG, "encrypt, AES_gcm_decrypt failed");
        return {};
    }
    std::vector<unsigned char> combined(result_len + KMC_IV_LEN, 0);
    memcpy(&combined[0], iv, KMC_IV_LEN);
    memcpy(&combined[KMC_IV_LEN], result.data(), result_len);

    return combined;
}

std::vector<unsigned char> EncryptSvc::encryptWithIv(unsigned char *data, int len, enum KMC_AES_ALGORITHM algorithm,
        unsigned char *key, unsigned char *iv) {
    // 获取加密算法

    EncryptDataStruct encryptData;

//    unsigned char result[len + 16 + 32];
    std::vector<unsigned char> result(len + 16);
    int result_len = AES_gcm_encrypt(algorithm,
                                     data,
                                     len, NULL, 0,
                                     key, iv, KMC_IV_LEN, result.data());
    if (result_len < 0) {
        kmclog_e(LOG_TAG, "encryptWithIv failed");
        return std::vector<unsigned char>();
    }
    kmclog_i(LOG_TAG, "encryptData, after encrypt, length is %d", result_len);
    if (result_len != len + 16) {
        result.resize(result_len);
    }

    return result;
}

Result<std::vector<unsigned char>> EncryptSvc::decryptData(unsigned char *data, int len, uint64_t sessionId, unsigned char *iv) {
    std::shared_ptr<SessionContext> sessionContext = m_sessionManager->getContext(sessionId);
    std::vector<unsigned char> result;
    if (sessionContext->type == SessionType::DATA && iv == nullptr) {
        kmclog_i(LOG_TAG, "decryptData, iv is null, type is data");
        result = doDecrypt(data, len, KmcContextManager::getInstance().getKmcAesAlgorithm(), sessionContext->dataSessionKey->dpck.msg);
    } else if (sessionContext->type == SessionType::GIS && iv == nullptr) {
        if (sessionContext->userType == UserType::SEND) {
            result = doDecrypt(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, sessionContext->gisSessionKeyR->msg);
        } else {
            result = doDecrypt(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, sessionContext->gisSessionKeyI->msg);
        }
    } else if (sessionContext->type == SessionType::DATA && iv != nullptr) {
        result = doDecryptWithIv(data, len, KmcContextManager::getInstance().getKmcAesAlgorithm(), sessionContext->dataSessionKey->dpck.msg, iv);
    } else if (sessionContext->type == SessionType::GIS && iv != nullptr) {
        if (sessionContext->userType == UserType::SEND) {
            result = doDecryptWithIv(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, sessionContext->gisSessionKeyR->msg, iv);
        } else {
            result = doDecryptWithIv(data, len, KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM, sessionContext->gisSessionKeyI->msg, iv);
        }
    }
    if (result.empty()) {
        return Result<std::vector<unsigned char>>(result, false,"decrypt failed");
    }
    return Result<std::vector<unsigned char>>(result, true,"");
}


// SRTP加密 + tag + mki
Result<bool> EncryptSvc::encryptSrtp(unsigned char *data, int *dataLength, int isRtp, uint64_t sessionId)
{
    kmclog_i(LOG_TAG, "encryptSrtp");
    if (*dataLength < 12) {
        kmclog_e(LOG_TAG, "data length is less than 12.");
        return Result<bool>(false, false,"data length is less than 12.");
    }
    uint32_t ssrc = ntohl(*(uint32_t *)(data + 8));  // 从 RTP 数据包的第 9 个字节开始提取 SSRC
    kmclog_i(LOG_TAG, "encryptSrtp, ssrc:%u", ssrc);

    std::shared_ptr<SessionContext> sessionContext = m_sessionManager->getContext(sessionId);
    kmclog_i(LOG_TAG, "encryptSrtp, get kmc Session:%d", sessionId);
    srtp_t &srtpsession = sessionContext->enSession;
    kmclog_i(LOG_TAG, "encryptSrtp, get srtp Session");
    void *s = srtp_get_user_data(srtpsession);
    kmclog_i(LOG_TAG, "encryptSrtp, get user data");
    sud_t *q = (sud_t *)s;
    int len = 4;
    uint8_t keyId[8];
    if (s != NULL) {
        if (q->sud_grp == 1) {
            kmclog_i(LOG_TAG, "encryptSrtp, group mode");
            len = 8;
            mki_pair_t *curPair = NULL;
            memcpy(keyId, sessionContext->groupKeyingMaterials->gmk_id, 4);
            memcpy(keyId + 4, sessionContext->groupKeyingMaterials->guk_id, 4);
            int r = switch_mki(srtpsession, keyId, len, &curPair);
            if (r < 0) {
                kmclog_e(LOG_TAG, "srtpEncrypt switch_mki error");
                return Result<bool>(false, false,"srtpEncrypt switch_mki error");
            }
            if(q->ssrcs.find(ssrc)== q->ssrcs.end())
            {
                srtp_policy_t *policy = &(curPair->mp_policy);
                policy->ssrc.value = ssrc;
                if (policy != NULL)
                {
                    q->ssrcs.insert(ssrc);
                    srtp_err_status_t result = srtp_add_stream(srtpsession, policy);
                    if (result != srtp_err_status_ok)
                    {
                        kmclog_e(LOG_TAG, "srtpEncrypt  srtp_add_stream error");
                    }
                }
            }
        }else { // 点呼
            kmclog_i(LOG_TAG, "encryptSrtp, p2p mode");
            len = 4;
            memcpy(keyId, sessionContext->mikeySakkeMsg->hdr.csb_id_value.msg, len);
            kmclog_i(LOG_TAG, "encryptSrtp, get mki");
            if(q->ssrcs.find(ssrc)== q->ssrcs.end())
            {
                kmclog_i(LOG_TAG, "encryptSrtp, get policy");
                // 点呼只会有一个policy
                srtp_policy_t *policy = &(q->sud_pair->mp_policy);
                policy->ssrc.value = ssrc;
                if (policy != NULL)
                {
                    kmclog_i(LOG_TAG, "encryptSrtp, q->ssrcs.insert:%d", ssrc);
                    //auto [it, inserted] =q->ssrcs.insert(ssrc);
                    q->ssrcs.insert(ssrc);
                    srtp_err_status_t result = srtp_add_stream(srtpsession, policy);
                    if (result != srtp_err_status_ok)
                    {
                        kmclog_e(LOG_TAG, "srtpEncrypt  srtp_add_stream error");
                    }
                }
            } else {
                kmclog_i(LOG_TAG, "encryptSrtp, existing ssrc");
            }
        }
    }
    //int *pkt_octet_len;
    kmclog_i(LOG_TAG, "encryptSrtp, check isRtp");
    if (isRtp)  // RTP
    {
        kmclog_i(LOG_TAG, "encryptSrtp, isRtp");
        if (*dataLength < (int)sizeof(uint32_t) * 3) {
            kmclog_e(LOG_TAG, "dataLength is less than 12");
            return Result<bool>(false, false,"dataLength");
        } else if (*dataLength == (int)sizeof(uint32_t) * 3) {
            /* for nat */
            kmclog_i(LOG_TAG, "encryptSrtp, dataLength is 12");
            return Result<bool>(true, true,"");
        }

        kmclog_i(LOG_TAG, "encryptSrtp, call protect");
        srtp_err_status_t result = srtp_protect_mki(srtpsession, data, dataLength, 0, 0);
        if (result != srtp_err_status_ok) {
            kmclog_e(LOG_TAG, "encryptSrtp, protect failed. %d", result);
            return Result<bool>(false, false,"encrypt failed");
        }
        int n = *dataLength;
        memcpy(data + n, keyId, len);
        *dataLength += len;
    } else  // RTCP
    {
        if (*dataLength < (int)sizeof(uint32_t) * 2) {
            kmclog_e(LOG_TAG, "dataLength");
            return Result<bool>(false, false,"dataLength");
        } else if (*dataLength == (int)sizeof(uint32_t) * 2) {
            /* for nat */
            return Result<bool>(true, true,"");
        }

        srtp_err_status_t result = srtp_protect_rtcp_mki(srtpsession, data, dataLength, 0, 0);
        if (result != srtp_err_status_ok) {
            kmclog_e(LOG_TAG, "encrypt failed");
            return Result<bool>(false, false,"encrypt failed");
        }
        int n = *dataLength;
        memcpy(data + n, keyId, len);
        *dataLength += len;
    }
    uint32_t roc = 0;
    srtp_err_status_t result = srtp_get_stream_roc(srtpsession, ssrc, &roc);
    if(result != srtp_err_status_ok) {
        kmclog_e(LOG_TAG, "srtp_get_stream_roc error");
        return Result<bool>(false, false,"srtp_get_stream_roc error");
    }

    uint32_t bitRoc = htonl(roc);

    memcpy(data + *dataLength, &bitRoc, sizeof(uint32_t));
    *dataLength += 4;
    return Result<bool>(true, true,"");
}

// SRTP解密   [endata, *endataLength][mki:4byte]
Result<bool> EncryptSvc::srtpDecrypt(unsigned char *endata, int *endataLength, int isRtp, uint64_t sessionId)
{
    if (*endataLength < 12) {
        return Result<bool>(false, false,"data length is less than 12.");
    }
    uint32_t ssrc = ntohl(*(uint32_t *)(endata + 8));  // 从 RTP 数据包的第 9 个字节开始提取 SSRC
    kmclog_i(LOG_TAG, "srtpDecrypt, ssrc:%u , sessionId:%d", ssrc, sessionId);
    uint32_t roc = ntohl(*((uint32_t *)(endata + *endataLength - 4)));
    *endataLength -= 4;
    std::shared_ptr<SessionContext> sessionContext = m_sessionManager->getContext(sessionId);
    srtp_t &srtpsession = sessionContext->deSession;
    kmclog_i(LOG_TAG, "srtpDecrypt, deSession:%p", sessionContext->deSession);
    void *s = srtp_get_user_data(srtpsession);
    int len = 4;
    if (s != NULL) {
        sud_t *q = (sud_t *)s;
        if (q->sud_grp == 1) {
            len = 8;
            uint8_t *mki_ = (uint8_t *)endata + (*endataLength) - len;
            mki_pair_t *curPair = NULL;
            int r = switch_mki(srtpsession, mki_, len, &curPair);
            if (r < 0) {
                kmclog_i(LOG_TAG, "Can't find mki, try to add.");
                addP2GGMKInfo(srtpsession, sessionContext, mki_);
                int r2 = switch_mki(srtpsession, mki_, len, &curPair);
                if (r2 < 0) {
                    kmclog_e(LOG_TAG, "srtpEncrypt switch_mki error");
                    return Result<bool>(false, false,"srtpEncrypt switch_mki error");
                }
            }
            if(q->ssrcs.find(ssrc)== q->ssrcs.end())
            {
                srtp_policy_t *policy = &(curPair->mp_policy);
                policy->ssrc.value = ssrc;
                if (policy != NULL)
                {
                    q->ssrcs.insert(ssrc);
                    srtp_err_status_t result = srtp_add_stream(srtpsession, policy);
                    if (result != srtp_err_status_ok)
                    {
                        kmclog_e(LOG_TAG, "srtpEncrypt  srtp_add_stream error");
                    }
                }
            }
        }
        else {
            if(q->ssrcs.find(ssrc)== q->ssrcs.end())
            {
                srtp_policy_t *policy = &(q->sud_pair->mp_policy);
                policy->ssrc.value = ssrc;
                kmclog_i(LOG_TAG, "srtpDecrypt, policy->ssrc.value:%u", policy->ssrc.value);
                if (policy != NULL)
                {
                    q->ssrcs.insert(ssrc);
                    srtp_err_status_t result = srtp_add_stream(srtpsession, policy);
                    if (result != srtp_err_status_ok)
                    {
                        kmclog_e(LOG_TAG, "srtpEncrypt  srtp_add_stream error");
                    }
                }
            }
        }
    }
    srtp_err_status_t result = srtp_set_stream_roc(srtpsession, ssrc, roc);
    if (result != srtp_err_status_ok) {
        kmclog_e(LOG_TAG, "srtp_get_stream_roc error");
        return Result<bool>(false, false,"srtp_get_stream_roc error");
    }
    *endataLength -= len;
    if (isRtp)  // RTP
    {
        if (*endataLength < (int)sizeof(uint32_t) * 3) {
            kmclog_e(LOG_TAG, "dataLength");
            return Result<bool>(false, false,"dataLength");
        } else if (*endataLength == (int)sizeof(uint32_t) * 3) {
            return Result<bool>(true, true,"");
        }

        srtp_err_status_t result = srtp_unprotect_mki(srtpsession, endata, endataLength, 0);
        if (result != srtp_err_status_ok) {
            kmclog_e(LOG_TAG, "srtp_unprotect_mki error: %d", result);
            return Result<bool>(false, false,"srtp_unprotect_mki error");
        }
    } else  // RTCP
    {
        if (*endataLength < (int)sizeof(uint32_t) * 2) {
            kmclog_e(LOG_TAG, "dataLength");
            return Result<bool>(false, false,"dataLength");
        } else if (*endataLength == (int)sizeof(uint32_t) * 2) {
            return Result<bool>(true, true,"");
        }

        srtp_err_status_t result = srtp_unprotect_rtcp_mki(srtpsession, endata, endataLength, 0);
        if (result != srtp_err_status_ok) {
            return result;
        }
    }
    return Result<bool>(true, true,"");
}


////3.2.1.3.1.4.1	增加SRTP密钥
int EncryptSvc::addP2GGMKInfo(srtp_t srtp_ctx, std::shared_ptr<SessionContext> sessionContext, const unsigned char *keyid)
{
    printBufferHex2("addP2GGMKInfo keyid:", (const char*)keyid, 8);
    printBufferHex2("addP2GGMKInfo rand:", (const char*)rand, 16);
    void *user_data = srtp_get_user_data(srtp_ctx);
    sud_t *p = (sud_t *)user_data;
    uint8_t *gmk = sessionContext->groupKeyingMaterials->ssv;

    uint8_t key[2048] = {0};
    size_t key_len = 0;
    uint8_t constant_value[] = {0x2A, 0xD0, 0x1C, 0x64};
    size_t constant_len = 4;
    uint8_t gukid[4] = {0};
    uint8_t randtmp[16] = {0};
    memcpy(gukid, keyid + 4, 4);
    memcpy(randtmp, sessionContext->groupKeyingMaterials->rand.msg, 16);
    esb_generateSessionKeyParams(gmk,
                                      SSV_LEN,
                                      constant_value,
                                      constant_len,
                                      p->sud_csid,
                                      gukid,
                                      4,
                                      randtmp,
                                      RAND_LEN,
                                      key,
                                      &key_len);

    uint8_t salt[2048] = {0};
    size_t salt_len = 0;
    uint8_t salt_constant[] = {0x39, 0xA2, 0xC1, 0x4B};
    // 生成salt
    esb_generateSessionKeyParams(
            gmk, 16, salt_constant, 4, p->sud_csid, gukid, 4, randtmp, RAND_LEN, salt, &salt_len);

    mki_pair_t *pair = create_pair();
    if (!pair) {
        return KMCSDK_FAIL;
    }

    int ret = m_sessionManager->initPilicy(p->sud_csid, KmcContextManager::getInstance().getKmcAesAlgorithm(), key, key_len, salt, salt_len, &pair->mp_policy, p->sud_ssrc);
    if (ret < 0) {
        destroy_pair(pair);
        free(pair);
        return KMCSDK_FAIL - 1;
    }
    srtp_set_user_data(srtp_ctx, user_data);
    pair->mp_mki = buf_to_mki(keyid, 8);  // 群组通信 mki为8字节
    if (p->sud_cryptPolicy == KMC_AES_ALGORITHM::ALGORITHM_AES_256_GCM) {
        pair->mp_keylen = 44;
    } else {
        pair->mp_keylen = 28;
    }
    add_pair_to_user_data(user_data, pair);
    return KMCSDK_SUCCESS;
}

std::vector<unsigned char> EncryptSvc::doDecrypt(unsigned char *data, int len, enum KMC_AES_ALGORITHM algorithm, unsigned char *key) {
    // 获取加密算法

    unsigned char iv[KMC_IV_LEN];                 // 存储 IV（12 字节）
    uint8_t* ciphertext = new uint8_t[len - KMC_IV_LEN]; // 堆上分配存储密文的空间

    // 复制前 12 字节到 IV
    memcpy(iv, data, KMC_IV_LEN);

    // 复制剩余字节到密文（从 combined[12] 开始）
    memcpy(ciphertext, data + KMC_IV_LEN, len - KMC_IV_LEN);

    std::vector<unsigned char> result(len);
    int result_len = AES_gcm_decrypt(algorithm, ciphertext, len - KMC_IV_LEN, NULL, 0,
                                     key, iv, KMC_IV_LEN, result.data());
    delete[] ciphertext; // 释放堆上分配的内存
    kmclog_i(TAG,  "doDecrypt, result_len:%d", result_len);
    if (result_len < 0) {
        kmclog_e(TAG, "doDecrypt, AES_gcm_decrypt failed");
        return {};
    }
    result.resize(result_len);
    kmclog_i(TAG,  "doDecrypt, resized");
    return result;
}

std::vector<unsigned char> EncryptSvc::doDecryptWithIv(unsigned char *data, int len, enum KMC_AES_ALGORITHM algorithm, unsigned char *key, unsigned char *iv) {

    std::vector<unsigned char> result(len);
    int result_len = AES_gcm_decrypt(algorithm, data, len, NULL, 0,
                                     key, iv, KMC_IV_LEN, result.data());
    if (result_len < 0) {
        kmclog_e(TAG, "doDecrypt, AES_gcm_decrypt failed");
        return {};
    }
    result.resize(result_len);
    return result;
}


} //KMC
