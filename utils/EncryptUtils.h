//
// Created by zWX1124406 on 2025/3/24.
//

#ifndef CPP_ENCRYPTUTILS_H
#define CPP_ENCRYPTUTILS_H
#include <securec.h>
#include "InternalStruct.h"
#include "KmcLogInterface.h"

namespace KMC {


void printBufferHex2(const char *src, const char *buffer, unsigned int bufferLen);

unsigned long long buf_to_mki(const uint8_t *p, int len);

void destroy_policy(srtp_policy_t *p);

void destroy_pair(mki_pair_t *p);

void destroy_pair_list(mki_pair_t *p);

mki_pair_t *create_pair();

void add_pair_to_user_data(void *user_data, mki_pair_t *data);

int switch_mki(srtp_t session, uint8_t *mki_, int len, mki_pair_t **curPair);

int find(uint8_t c);

int buffer_hex_copy(const uint8_t *src, int src_len, uint8_t *des, int des_len);

void *create_session_user_data(
        const uc_t *keyid, int keyid_len, int cryptPolicy, int csid, int grp, srtp_ssrc_t ssrc);

void destroy_user_data(void *q);


} //KMC
#endif //CPP_ENCRYPTUTILS_H
