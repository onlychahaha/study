#ifndef INTERNALSTRUCT_H
#define INTERNALSTRUCT_H
extern "C" {
#include "core/kmc-types.h"
#include "native-logic.h"
#include "native-eccsi-sakke-msg-builder.h"
}


#include <string>
#include <memory>
#include <set>
#include <unordered_set>

#include <srtp2/srtp.h>
#include <openssl/srtp.h>

#include <Commstruct.h>

namespace KMC {

/**
 * mki与policy的映射
 */
typedef struct mki_pair {
    unsigned long long mp_mki;
    unsigned int mp_keylen;
    srtp_policy_t mp_policy;
    struct mki_pair *mp_next;
} mki_pair_t;

typedef unsigned char uc_t;
// 保存创建session时所用的参数
typedef struct SessionUserData {
    uc_t sud_keyid[8];    // gmkid+gukid
    int sud_cryptPolicy;  // srtp加密算法
    int sud_csid;
    int sud_grp;  // 是否为群组通信 0否， 1是
    std::unordered_set<int> ssrcs;
    srtp_ssrc_t sud_ssrc;
    mki_pair_t *sud_pair;
    mki_pair_t *curPair;
} sud_t;

struct SessionContext {
    std::string kmsUri;
    std::string userUri;
    SessionType type;
    ScopeType scopeType;
    UserType userType;
    std::shared_ptr<P2PInfo> p2pInfo;
    std::shared_ptr<GroupInfo> groupInfo;
    std::string mikey;
    uint8_t ptp_ssv[SSV_LEN];
    int64_t sessionId;
    std::shared_ptr<mikey_sakke_msg_t> mikeySakkeMsg;
    std::shared_ptr<p2p_session_key_t> p2pSessionKey;
    std::shared_ptr<mcdata_session_key_t> dataSessionKey;
    std::shared_ptr<info_t> gisSessionKeyI;
    std::shared_ptr<info_t> gisSessionKeyR;
    std::shared_ptr<info_t> gisCskId;
    std::shared_ptr<grp_session_key_t> grpSessionKey;
    std::shared_ptr<grp_keying_materials_t> groupKeyingMaterials;
    srtp_t enSession;
    srtp_t deSession;
};


} //KMC

#endif // INTERNALSTRUCT_H