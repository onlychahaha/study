#include "kmcTeeStorage.h"
#include "KmcContextManager.h"

#ifdef ENABLE_COMPILE_TEE
#include "tee/kmc-tee.h"
#endif

namespace KMC {
    
void KmcTeeManager::Init(uint8_t tee_type) {
#ifdef ENABLE_COMPILE_TEE
    tee_init(tee_type);
    kmclog_i(LOG_TAG, "tee_init completed");
#else
    kmclog_i(LOG_TAG, "TEE not enabled in compilation");
#endif
}

bool KmcTeeManager::IsAvailable(uint8_t tee_type) {
#ifdef ENABLE_COMPILE_TEE
    bool is_available = (tee_is_available(tee_type) == 0);
    kmclog_i(LOG_TAG, "isAvailable, result: %s", is_available ? "true" : "false");
    return is_available;
#else
    kmclog_i(LOG_TAG, "isAvailable, TEE not enabled");
    return false;
#endif
}

TeeQueryCertMaterialBasic KmcTeeManager::QueryCertMaterialBasic(uint8_t tee_type,
    const std::string& user_uri, 
    uint8_t online_type) {
    
    kmclog_i(LOG_TAG, "queryCertMaterialBasic, start. user_uri length: %zu, online_type: %d", 
             user_uri.length(), online_type);
    
    TeeQueryCertMaterialBasic result = {};
    
#ifdef ENABLE_COMPILE_TEE
    query_cert_material_basic_resp rsp = {};

    // 将std::string转换为uint8_t数组
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back(0); // 确保以/0结尾
    tee_query_cert_material_basic(tee_type,
                                  user_uri_bytes.data(),
                                  online_type, &rsp);
    
    result.cert_count = rsp.cert_count;
    result.cert_uri = reinterpret_cast<const char*>(rsp.cert_cert_uri);
    result.cert_kms_uri = reinterpret_cast<const char*>(rsp.cert_kms_uri);
    result.cert_user_period = rsp.cert_user_period;
    result.cert_user_offset = rsp.cert_user_offset;
    result.material_count = rsp.material_count;
    result.material1_valid_from = reinterpret_cast<const char*>(rsp.material_1_valid_from);
    result.material1_valid_to = reinterpret_cast<const char*>(rsp.material_1_valid_to);
    result.material1_period_no = rsp.material_1_period_no;
    result.material1_user_id = reinterpret_cast<const char*>(rsp.material_1_user_id);
    result.material2_valid_from = reinterpret_cast<const char*>(rsp.material_2_valid_from);
    result.material2_valid_to = reinterpret_cast<const char*>(rsp.material_2_valid_to);
    result.material2_period_no = rsp.material_2_period_no;
    result.material2_user_id = reinterpret_cast<const char*>(rsp.material_2_user_id);
#endif
    
    kmclog_i(LOG_TAG, "queryCertMaterialBasic, end");
    return result;
}

TeeQueryCertMaterialFull KmcTeeManager::QueryCertMaterialFull(uint8_t tee_type,
    const std::string& user_uri, 
    uint8_t online_type) {
    
    kmclog_i(LOG_TAG, "queryCertMaterialFull, start. user_uri length: %zu, online_type: %d", 
             user_uri.length(), online_type);
    
    TeeQueryCertMaterialFull result = {};
    
#ifdef ENABLE_COMPILE_TEE
    query_cert_material_full_resp rsp = {};
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back(0); // 确保以/0结尾
    tee_query_cert_material_full(tee_type,
                                 user_uri_bytes.data(),
                                 online_type, &rsp);

    // 1. 直接拷贝数值类型字段
    result.cert_count = rsp.cert_count;
    result.cert_user_period = static_cast<int64_t>(rsp.cert_user_period);
    result.cert_user_offset = static_cast<int64_t>(rsp.cert_user_offset);
    result.material_count = rsp.material_count;
    result.material1_period_no = static_cast<int64_t>(rsp.material_1_period_no);
    result.material2_period_no = static_cast<int64_t>(rsp.material_2_period_no);

    // 2. 处理字符串类型字段（定长数组转std::string）
    // 证书相关字段
    result.cert_uri = reinterpret_cast<const char*>(rsp.cert_cert_uri);
    result.cert_kms_uri = reinterpret_cast<const char*>(rsp.cert_kms_uri);
    result.cert_pub_enc_key = reinterpret_cast<const char*>(rsp.cert_pub_enc_key);
    result.cert_pub_auth_key = reinterpret_cast<const char*>(rsp.cert_pub_auth_key);

    // 材料1字段
    result.material1_valid_from = reinterpret_cast<const char*>(rsp.material_1_valid_from);
    result.material1_valid_to = reinterpret_cast<const char*>(rsp.material_1_valid_to);
    result.material1_user_id = reinterpret_cast<const char*>(rsp.material_1_user_id);
    result.material1_ssk = reinterpret_cast<const char*>(rsp.material_1_ssk);
    result.material1_rsk = reinterpret_cast<const char*>(rsp.material_1_rsk);
    result.material1_pvt = reinterpret_cast<const char*>(rsp.material_1_pvt);

    // 材料2字段
    result.material2_valid_from = reinterpret_cast<const char*>(rsp.material_2_valid_from);
    result.material2_valid_to = reinterpret_cast<const char*>(rsp.material_2_valid_to);
    result.material2_user_id = reinterpret_cast<const char*>(rsp.material_2_user_id);
    result.material2_ssk = reinterpret_cast<const char*>(rsp.material_2_ssk);
    result.material2_rsk = reinterpret_cast<const char*>(rsp.material_2_rsk);
    result.material2_pvt = reinterpret_cast<const char*>(rsp.material_2_pvt);
#endif
    
    kmclog_i(LOG_TAG, "queryCertMaterialFull, end");
    return result;
}

void KmcTeeManager::LoadCertMaterial(uint8_t tee_type,
    const std::string& user_uri, 
    uint8_t online_type, 
    uint64_t tm) {
    
    kmclog_i(LOG_TAG, "loadCertMaterial, start. user_uri length: %zu, online_type: %d, tm: %llu", 
             user_uri.length(), online_type, tm);
    
#ifdef ENABLE_COMPILE_TEE
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back('\0');
    tee_load_cert_material(tee_type,
                           user_uri_bytes.data(),
                           online_type, tm);
#endif
    
    kmclog_i(LOG_TAG, "loadCertMaterial, end");
}

void KmcTeeManager::ClearCert(const std::string& user_uri) {
    kmclog_i(LOG_TAG, "clearCert, start. user_uri length: %zu", user_uri.length());
    
    uint8_t type = 2;
    if (KMC::KmcContextManager::getInstance().GetOnlineMode() == KMC::OnlineMode::ONLINE) {
        type = 1;
    }
    
#ifdef ENABLE_COMPILE_TEE
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "clearCert, user_uri_bytes size: %zu, type: %d", user_uri_bytes.size(), type);
    
    tee_clear_cert(KMC_TEE_QSEE,
                   user_uri_bytes.data(),
                   type);
    
    kmclog_i(LOG_TAG, "clearCert, tee_clear_cert call completed");
#else
    kmclog_i(LOG_TAG, "clearCert, TEE not enabled in compilation");
#endif
    
    kmclog_i(LOG_TAG, "clearCert, end");
}

void KmcTeeManager::ClearMaterials(uint8_t tee_type,
    const std::string& user_uri, 
    uint8_t online_type) {
    
    kmclog_i(LOG_TAG, "clearMaterials, start. user_uri length: %zu, online_type: %d", 
             user_uri.length(), online_type);
    
#ifdef ENABLE_COMPILE_TEE
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back('\0');
    tee_clear_materials(tee_type,
                        user_uri_bytes.data(),
                        online_type);
#endif
    
    kmclog_i(LOG_TAG, "clearMaterials, end");
}

void KmcTeeManager::StoreCert(uint8_t tee_type,
    const std::string& user_uri,
    uint8_t online_type,
    const std::string& version,
    const std::string& cert_uri,
    const std::string& kms_uri,
    const std::string& issuer,
    const std::string& valid_from,
    const std::string& valid_to,
    int32_t revoked,
    int64_t user_period,
    int64_t user_offset,
    const std::string& user_id_format,
    const std::string& pub_enc_key,
    const std::string& pub_auth_key,
    const std::string& kms_domain_list) {
    
    kmclog_i(LOG_TAG, "storeCert, start. user_uri length: %zu, online_type: %d", 
             user_uri.length(), online_type);
    
#ifdef ENABLE_COMPILE_TEE
    // 转换字符串为底层接口需要的格式，包含空终止符
    kmclog_i(LOG_TAG, "storeCert, converting strings to byte arrays with null terminator");

    // 将字符串参数转换为uint8_t数组，包含空终止符
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, user_uri_bytes size: %zu", user_uri_bytes.size());
    
    std::vector<uint8_t> version_bytes(version.begin(), version.end());
    version_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, version_bytes size: %zu", version_bytes.size());
    
    std::vector<uint8_t> cert_uri_bytes(cert_uri.begin(), cert_uri.end());
    cert_uri_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, cert_uri_bytes size: %zu", cert_uri_bytes.size());
    
    std::vector<uint8_t> kms_uri_bytes(kms_uri.begin(), kms_uri.end());
    kms_uri_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, kms_uri_bytes size: %zu", kms_uri_bytes.size());
    
    std::vector<uint8_t> issuer_bytes(issuer.begin(), issuer.end());
    issuer_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, issuer_bytes size: %zu", issuer_bytes.size());
    
    std::vector<uint8_t> valid_from_bytes(valid_from.begin(), valid_from.end());
    valid_from_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, valid_from_bytes size: %zu", valid_from_bytes.size());
    
    std::vector<uint8_t> valid_to_bytes(valid_to.begin(), valid_to.end());
    valid_to_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, valid_to_bytes size: %zu", valid_to_bytes.size());
    
    std::vector<uint8_t> user_id_format_bytes(user_id_format.begin(), user_id_format.end());
    user_id_format_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, user_id_format_bytes size: %zu", user_id_format_bytes.size());
    
    std::vector<uint8_t> kms_domain_list_bytes(kms_domain_list.begin(), kms_domain_list.end());
    kms_domain_list_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeCert, kms_domain_list_bytes size: %zu", kms_domain_list_bytes.size());

    // 将 pub_enc_key 转换为 uint8_t 数组
    std::vector<uint8_t> pub_enc_key_bytes(pub_enc_key.begin(), pub_enc_key.end());
    pub_enc_key_bytes.push_back('\0');
    int32_t pub_enc_key_len = static_cast<int32_t>(pub_enc_key_bytes.size()); // 长度包含空终止符
    kmclog_i(LOG_TAG, "storeCert, pub_enc_key_bytes size: %zu, pub_enc_key_len: %d", 
             pub_enc_key_bytes.size(), pub_enc_key_len);

    // 将 pub_auth_key 转换为 uint8_t 数组
    std::vector<uint8_t> pub_auth_key_bytes(pub_auth_key.begin(), pub_auth_key.end());
    pub_auth_key_bytes.push_back('\0');
    int32_t pub_auth_key_len = static_cast<int32_t>(pub_auth_key_bytes.size()); // 长度包含空终止符
    kmclog_i(LOG_TAG, "storeCert, pub_auth_key_bytes size: %zu, pub_auth_key_len: %d", 
             pub_auth_key_bytes.size(), pub_auth_key_len);

    kmclog_i(LOG_TAG, "storeCert, calling tee_store_cert with parameters: tee_type=%d, online_type=%d, revoked=%d, user_period=%lld, user_offset=%lld",
             tee_type, online_type, revoked, (long long)user_period, (long long)user_offset);

    // 调用函数，传递所有参数
    tee_store_cert(
            tee_type,
            user_uri_bytes.data(),
            online_type,
            version_bytes.data(),
            cert_uri_bytes.data(),
            kms_uri_bytes.data(),
            issuer_bytes.data(),
            valid_from_bytes.data(),
            valid_to_bytes.data(),
            revoked,
            user_period,
            user_offset,
            user_id_format_bytes.data(),
            pub_enc_key_bytes.data(),
            pub_enc_key_len,
            pub_auth_key_bytes.data(),
            pub_auth_key_len,
            kms_domain_list_bytes.data()
    );
    
    kmclog_i(LOG_TAG, "storeCert, tee_store_cert call completed");
#else
    kmclog_i(LOG_TAG, "storeCert, TEE not enabled in compilation");
#endif
    
    kmclog_i(LOG_TAG, "storeCert, end");
}

void KmcTeeManager::StoreMaterials(uint8_t tee_type,
                                   const std::string& user_uri,
                                   uint8_t online_type,
                                   const std::string& version,
                                   const std::string& cert_uri,
                                   const std::string& kms_uri,
                                   const std::string& issuer,
                                   const std::string& valid_from,
                                   const std::string& valid_to,
                                   int32_t revoked,
                                   int64_t period_no,
                                   const std::string& user_uri_mcx,
                                   const std::string& user_id,
                                   const std::string& ssk,
                                   const std::string& rsk,
                                   const std::string& pvt,
                                   const std::string& version2,
                                   const std::string& cert_uri2,
                                   const std::string& kms_uri2,
                                   const std::string& issuer2,
                                   const std::string& valid_from2,
                                   const std::string& valid_to2,
                                   int32_t revoked2,
                                   int64_t period_no2,
                                   const std::string& user_uri_mcx2,
                                   const std::string& user_id2,
                                   const std::string& ssk2,
                                   const std::string& rsk2,
                                   const std::string& pvt2) {

    kmclog_i(LOG_TAG, "storeMaterials, start. user_uri length: %zu, online_type: %d",
             user_uri.length(), online_type);

#ifdef ENABLE_COMPILE_TEE
    kmclog_i(LOG_TAG, "storeMaterials, converting strings to byte arrays with null terminator");
    
    // 转换所有字符串参数为uint8_t数组，包含空终止符
    std::vector<uint8_t> user_uri_bytes(user_uri.begin(), user_uri.end());
    user_uri_bytes.push_back('\0');
    kmclog_i(LOG_TAG, "storeMaterials, user_uri_bytes size: %zu", user_uri_bytes.size());
    
    std::vector<uint8_t> version_bytes(version.begin(), version.end());
    version_bytes.push_back('\0');
    
    std::vector<uint8_t> cert_uri_bytes(cert_uri.begin(), cert_uri.end());
    cert_uri_bytes.push_back('\0');
    
    std::vector<uint8_t> kms_uri_bytes(kms_uri.begin(), kms_uri.end());
    kms_uri_bytes.push_back('\0');
    
    std::vector<uint8_t> issuer_bytes(issuer.begin(), issuer.end());
    issuer_bytes.push_back('\0');
    
    std::vector<uint8_t> valid_from_bytes(valid_from.begin(), valid_from.end());
    valid_from_bytes.push_back('\0');
    
    std::vector<uint8_t> valid_to_bytes(valid_to.begin(), valid_to.end());
    valid_to_bytes.push_back('\0');
    
    std::vector<uint8_t> user_uri_mcx_bytes(user_uri_mcx.begin(), user_uri_mcx.end());
    user_uri_mcx_bytes.push_back('\0');
    
    std::vector<uint8_t> user_id_bytes(user_id.begin(), user_id.end());
    user_id_bytes.push_back('\0');
    
    std::vector<uint8_t> ssk_bytes(ssk.begin(), ssk.end());
    ssk_bytes.push_back('\0');
    
    std::vector<uint8_t> rsk_bytes(rsk.begin(), rsk.end());
    rsk_bytes.push_back('\0');
    
    std::vector<uint8_t> pvt_bytes(pvt.begin(), pvt.end());
    pvt_bytes.push_back('\0');
    
    kmclog_i(LOG_TAG, "storeMaterials, first material strings converted. ssk_bytes size: %zu, rsk_bytes size: %zu, pvt_bytes size: %zu",
             ssk_bytes.size(), rsk_bytes.size(), pvt_bytes.size());

    // 第二个密钥材料的转换
    std::vector<uint8_t> version2_bytes(version2.begin(), version2.end());
    version2_bytes.push_back('\0');
    
    std::vector<uint8_t> cert_uri2_bytes(cert_uri2.begin(), cert_uri2.end());
    cert_uri2_bytes.push_back('\0');
    
    std::vector<uint8_t> kms_uri2_bytes(kms_uri2.begin(), kms_uri2.end());
    kms_uri2_bytes.push_back('\0');
    
    std::vector<uint8_t> issuer2_bytes(issuer2.begin(), issuer2.end());
    issuer2_bytes.push_back('\0');
    
    std::vector<uint8_t> valid_from2_bytes(valid_from2.begin(), valid_from2.end());
    valid_from2_bytes.push_back('\0');
    
    std::vector<uint8_t> valid_to2_bytes(valid_to2.begin(), valid_to2.end());
    valid_to2_bytes.push_back('\0');
    
    std::vector<uint8_t> user_uri_mcx2_bytes(user_uri_mcx2.begin(), user_uri_mcx2.end());
    user_uri_mcx2_bytes.push_back('\0');
    
    std::vector<uint8_t> user_id2_bytes(user_id2.begin(), user_id2.end());
    user_id2_bytes.push_back('\0');
    
    std::vector<uint8_t> ssk2_bytes(ssk2.begin(), ssk2.end());
    ssk2_bytes.push_back('\0');
    
    std::vector<uint8_t> rsk2_bytes(rsk2.begin(), rsk2.end());
    rsk2_bytes.push_back('\0');
    
    std::vector<uint8_t> pvt2_bytes(pvt2.begin(), pvt2.end());
    pvt2_bytes.push_back('\0');

    kmclog_i(LOG_TAG, "storeMaterials, second material strings converted. ssk2_bytes size: %zu, rsk2_bytes size: %zu, pvt2_bytes size: %zu",
             ssk2_bytes.size(), rsk2_bytes.size(), pvt2_bytes.size());

    // 获取指针和长度
    uint8_t* user_uri_ptr = user_uri_bytes.data();
    uint8_t* version_ptr = version_bytes.data();
    uint8_t* cert_uri_ptr = cert_uri_bytes.data();
    uint8_t* kms_uri_ptr = kms_uri_bytes.data();
    uint8_t* issuer_ptr = issuer_bytes.data();
    uint8_t* valid_from_ptr = valid_from_bytes.data();
    uint8_t* valid_to_ptr = valid_to_bytes.data();
    uint8_t* user_uri_mcx_ptr = user_uri_mcx_bytes.data();
    uint8_t* user_id_ptr = user_id_bytes.data();
    uint8_t* ssk_ptr = ssk_bytes.data();
    int32_t ssk_len = static_cast<int32_t>(ssk_bytes.size() - 1); // 长度不包含空终止符
    uint8_t* rsk_ptr = rsk_bytes.data();
    int32_t rsk_len = static_cast<int32_t>(rsk_bytes.size() - 1); // 长度不包含空终止符
    uint8_t* pvt_ptr = pvt_bytes.data();
    int32_t pvt_len = static_cast<int32_t>(pvt_bytes.size() - 1); // 长度不包含空终止符
    
    uint8_t* version2_ptr = version2_bytes.data();
    uint8_t* cert_uri2_ptr = cert_uri2_bytes.data();
    uint8_t* kms_uri2_ptr = kms_uri2_bytes.data();
    uint8_t* issuer2_ptr = issuer2_bytes.data();
    uint8_t* valid_from2_ptr = valid_from2_bytes.data();
    uint8_t* valid_to2_ptr = valid_to2_bytes.data();
    uint8_t* user_uri_mcx2_ptr = user_uri_mcx2_bytes.data();
    uint8_t* user_id2_ptr = user_id2_bytes.data();
    uint8_t* ssk2_ptr = ssk2_bytes.data();
    int32_t ssk2_len = static_cast<int32_t>(ssk2_bytes.size() - 1); // 长度不包含空终止符
    uint8_t* rsk2_ptr = rsk2_bytes.data();
    int32_t rsk2_len = static_cast<int32_t>(rsk2_bytes.size() - 1); // 长度不包含空终止符
    uint8_t* pvt2_ptr = pvt2_bytes.data();
    int32_t pvt2_len = static_cast<int32_t>(pvt2_bytes.size() - 1); // 长度不包含空终止符

    // 判断材料数量
    uint8_t materials_count = 1;
    if (!ssk2.empty() && !rsk2.empty() && !pvt2.empty() && !user_id2.empty()) {
        materials_count = 2;
    }
    
    kmclog_i(LOG_TAG, "storeMaterials, materials_count: %d", materials_count);
    kmclog_i(LOG_TAG, "storeMaterials, lengths - ssk_len: %d, rsk_len: %d, pvt_len: %d, ssk2_len: %d, rsk2_len: %d, pvt2_len: %d",
             ssk_len, rsk_len, pvt_len, ssk2_len, rsk2_len, pvt2_len);
    
    kmclog_i(LOG_TAG, "storeMaterials, calling tee_store_materials with parameters: tee_type=%d, online_type=%d, materials_count=%d",
             tee_type, online_type, materials_count);

    tee_store_materials(
            tee_type,
            user_uri_ptr,
            online_type,
            materials_count,
            version_ptr,
            cert_uri_ptr,
            kms_uri_ptr,
            issuer_ptr,
            valid_from_ptr,
            valid_to_ptr,
            revoked,
            period_no,
            user_uri_mcx_ptr,
            user_id_ptr,
            ssk_ptr, ssk_len,
            rsk_ptr, rsk_len,
            pvt_ptr, pvt_len,
            version2_ptr,
            cert_uri2_ptr,
            kms_uri2_ptr,
            issuer2_ptr,
            valid_from2_ptr,
            valid_to2_ptr,
            revoked2,
            period_no2,
            user_uri_mcx2_ptr,
            user_id2_ptr,
            ssk2_ptr, ssk2_len,
            rsk2_ptr, rsk2_len,
            pvt2_ptr, pvt2_len);
    
    kmclog_i(LOG_TAG, "storeMaterials, tee_store_materials call completed");
#else
    kmclog_i(LOG_TAG, "storeMaterials, TEE not enabled in compilation");
#endif

    kmclog_i(LOG_TAG, "storeMaterials, end");
}

bool KmcTeeManager::StoreKeyMaterialsFromCache(
		std::vector<KeyInfos2> &keyInfos,
		const std::string	  &userUri,
		uint8_t					teeType,
		int						mode)
{
	if (keyInfos.empty()) {
		return false; // 无缓存数据
	}

	// 2. 提取第一个密钥信息
    const KeyInfos2& key1 = keyInfos[0];
    std::string version1 = "";
    std::string certUri1 = key1.certUri;
    std::string kmsUri1 = key1.kmsUri;
    std::string issuer1 = "";
    std::string validFrom1 = key1.validFrom;
    std::string validTo1 = key1.validTo;
    int32_t revoked1 = 0;
    int64_t periodNo1 = key1.keyPeriodNo;
    std::string userUriMcx1 = key1.userUri;
    std::string userID1 = key1.userID;
    std::string ssk1 = key1.ssk;
    std::string rsk1 = key1.rsk;
    std::string pvt1 = key1.pvt;

    // 3. 提取第二个密钥信息（如果存在）
    std::string version2 = "";
    std::string certUri2 = "";
    std::string kmsUri2 = "";
    std::string issuer2 = "";
    std::string validFrom2 = "";
    std::string validTo2 = "";
    int32_t revoked2 = 0;
    int64_t periodNo2 = 0;
    std::string userUriMcx2 = "";
    std::string userID2 = "";
    std::string ssk2 = "";
    std::string rsk2 = "";
    std::string pvt2 = "";

    if (keyInfos.size() > 1) {
        const KeyInfos2& key2 = keyInfos[1];
        certUri2 = key2.certUri;
        kmsUri2 = key2.kmsUri;
        validFrom2 = key2.validFrom;
        validTo2 = key2.validTo;
        periodNo2 = key2.keyPeriodNo;
        userUriMcx2 = key2.userUri;
        userID2 = key2.userID;
        ssk2 = key2.ssk;
        rsk2 = key2.rsk;
        pvt2 = key2.pvt;
    }

    // 4. 调用TEE存储接口
    KmcTeeManager::StoreMaterials(
        teeType, userUri, mode,
        version1, certUri1, kmsUri1, issuer1, validFrom1, validTo1,
        revoked1, periodNo1, userUriMcx1, userID1, ssk1, rsk1, pvt1,
        version2, certUri2, kmsUri2, issuer2, validFrom2, validTo2,
        revoked2, periodNo2, userUriMcx2, userID2, ssk2, rsk2, pvt2
    );

    return true;
}

} // namespace KMC