//
// Created by zWX1124406 on 2025/3/24.
//
#include "EncryptUtils.h"

namespace KMC {


void printBufferHex2(const char *src, const char *buffer, unsigned int bufferLen)
{
    char strBuf[30]={0};
    unsigned int i = 0;
    for (; i < bufferLen; i++) {
        int j = (i % 8) * 3;
        if (i % 8 == 0 && i != 0) {
            memset(strBuf, 0, 30);
        }
        sprintf_s(strBuf + j, 4 ,"%02x ",buffer[i] & 0xff);
    }
    kmclog_d(LOG_TAG,strBuf);
    //file << src << " end" << std::endl;
}

unsigned long long buf_to_mki(const uint8_t *p, int len)
{  // 这里的p至少是4个字节
    if (len == 4) {
        return *((unsigned int *)p);
    } else {
        return *((unsigned long long *)p);
    }
}
void destroy_policy(srtp_policy_t *p)
{
    if (p) {
        free(p->key);
    }
}
void destroy_pair(mki_pair_t *p)
{
    destroy_policy(&p->mp_policy);
}
void destroy_pair_list(mki_pair_t *p)
{
    if (!p) {
        return;
    }
    mki_pair_t *q = NULL;
    while (p) {
        q = p;
        p = p->mp_next;
        destroy_pair(q);
        free(q);
    }
}
mki_pair_t *create_pair()
{
    mki_pair_t *p = (mki_pair_t *)malloc(sizeof(mki_pair_t));
    memset(p, 0, sizeof(mki_pair_t));
    return p;
}
void add_pair_to_user_data(void *user_data, mki_pair_t *data)
{
    sud_t *p = (sud_t *)user_data;
    data->mp_next = p->sud_pair;
    p->sud_pair = data;
    p->curPair = data;
}

// p2p mki_ 是4字节， pgr mki_是8字节
int switch_mki(srtp_t session, uint8_t *mki_, int len, mki_pair_t **curPair)
{
    void *s = srtp_get_user_data(session);
    sud_t *q = (sud_t *)s;
    unsigned long long curmki = buf_to_mki(q->sud_keyid, len);
    unsigned long long mki = buf_to_mki(mki_, len);
    if (curmki == mki) {
        *curPair = q->curPair;
        return 0;
    }
    mki_pair_t *p = q->sud_pair;

    while (p) {
        if (p->mp_mki == mki) {
            srtp_update(session, &p->mp_policy);
            memcpy(q->sud_keyid, mki_, len);
            srtp_set_user_data(session, q);
            q->curPair = p; // 获取policy
            *curPair = p;
            return 0;
        }
        p = p->mp_next;
    }
    printBufferHex2("switch_mki error:", (const char*)mki_, len);
    return -1;
}

int find(uint8_t c)
{
    uint8_t arr[] = "0123456789ABCDEFabcdef";
    uint8_t arr2[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 10, 11, 12, 13, 14, 15};
    for (uint8_t i = 0; i < sizeof(arr2); ++i) {
        if (c == arr[i]) {
            return arr2[i];
        }
    }
    return -1;
}
int buffer_hex_copy(const uint8_t *src, int src_len, uint8_t *des, int des_len)
{
    if (!src || !des) {
        return -1;
    }
    int n = src_len / 2 < des_len ? src_len : des_len;
    for (int i = 0; i < n - 1; i += 2) {
        char c = src[i];
        uint8_t x, y;
        x = find(c);
        if (x < 0) {
            return -1;
        }
        y = find(src[i + 1]);
        if (y < 0) {
            return -1;
        }
        des[i / 2] = x << 4 + y;
    }
    return 0;
}

/**
 * @brief
 */
void *create_session_user_data(
        const uc_t *keyid, int keyid_len, int cryptPolicy, int csid, int grp, srtp_ssrc_t ssrc)
{
    sud_t *p = new sud_t();
    if (!p) {
        return p;
    }
    memcpy(p->sud_keyid, keyid, keyid_len);
    p->sud_cryptPolicy = cryptPolicy;
    p->sud_csid = csid;
    p->sud_pair = NULL;
    p->sud_grp = grp;
    p->sud_ssrc = ssrc;
    p->ssrcs.insert(ssrc.value);
    return (void *)p;
}
void destroy_user_data(void *q)
{
    if (q != NULL) {
        sud_t *p = (sud_t *)q;
        destroy_pair_list(p->sud_pair);
        delete p;
    }
}


} //KMC