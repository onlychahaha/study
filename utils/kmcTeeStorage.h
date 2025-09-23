#ifndef KMC_TEE_STORAGE_H_
#define KMC_TEE_STORAGE_H_

#include <string>
#include <cstdint>
#include <memory>
#include <vector>

#include "Commstruct.h"

namespace KMC {

// TEE查询证书材料基础信息结构体
struct TeeQueryCertMaterialBasic {
    int32_t cert_count;
    std::string cert_uri;
    std::string cert_kms_uri;
    int64_t cert_user_period;
    int64_t cert_user_offset;
    int32_t material_count;
    std::string material1_valid_from;
    std::string material1_valid_to;
    int64_t material1_period_no;
    std::string material1_user_id;
    std::string material2_valid_from;
    std::string material2_valid_to;
    int64_t material2_period_no;
    std::string material2_user_id;
};

// TEE查询证书材料完整信息结构体
struct TeeQueryCertMaterialFull {
    int32_t cert_count;
    std::string cert_uri;
    std::string cert_kms_uri;
    int64_t cert_user_period;
    int64_t cert_user_offset;
	std::string cert_pub_enc_key;
    std::string cert_pub_auth_key;
    int32_t material_count;
    std::string material1_valid_from;
    std::string material1_valid_to;
    int64_t material1_period_no;
    std::string material1_user_id;
    std::string material2_valid_from;
    std::string material2_valid_to;
    int64_t material2_period_no;
    std::string material2_user_id;
    std::string material1_ssk;
    std::string material1_rsk;
    std::string material1_pvt;
    std::string material2_ssk;
    std::string material2_rsk;
    std::string material2_pvt;
};

class KmcTeeManager {
public:

    static void Init(uint8_t tee_type);
    // 检查TEE是否可用
    static bool IsAvailable(uint8_t tee_type);

	// 查询证书材料基础信息
	static TeeQueryCertMaterialBasic
	QueryCertMaterialBasic(uint8_t			  tee_type,
						   const std::string &user_uri,
						   uint8_t			  online_type);

	// 查询证书材料完整信息
	static TeeQueryCertMaterialFull
	QueryCertMaterialFull(uint8_t			 tee_type,
						  const std::string &user_uri,
						  uint8_t			 online_type);

	// 加载证书材料
	static void LoadCertMaterial(uint8_t			tee_type,
								 const std::string &user_uri,
								 uint8_t			online_type,
								 uint64_t			tm);

	// 清除证书
	static void ClearCert(const std::string &user_uri);

	// 清除密钥材料
	static void ClearMaterials(uint8_t			  tee_type,
							   const std::string &user_uri,
							   uint8_t			  online_type);

	static void StoreCert(uint8_t			 tee_type,
						  const std::string &user_uri,
						  uint8_t			 online_type,
						  const std::string &version,
						  const std::string &cert_uri,
						  const std::string &kms_uri,
						  const std::string &issuer,
						  const std::string &valid_from,
						  const std::string &valid_to,
						  int32_t			 revoked,
						  int64_t			 user_period,
						  int64_t			 user_offset,
						  const std::string &user_id_format,
						  const std::string &pub_enc_key,
						  const std::string &pub_auth_key,
						  const std::string &kms_domain_list);

	static void StoreMaterials(uint8_t			  tee_type,
							   const std::string &user_uri,
							   uint8_t			  online_type,
							   const std::string &version,
							   const std::string &cert_uri,
							   const std::string &kms_uri,
							   const std::string &issuer,
							   const std::string &valid_from,
							   const std::string &valid_to,
							   int32_t			  revoked,
							   int64_t			  period_no,
							   const std::string &user_uri_mcx,
							   const std::string &user_id,
							   const std::string &ssk,
							   const std::string &rsk,
							   const std::string &pvt,
							   const std::string &version2,
							   const std::string &cert_uri2,
							   const std::string &kms_uri2,
							   const std::string &issuer2,
							   const std::string &valid_from2,
							   const std::string &valid_to2,
							   int32_t			  revoked2,
							   int64_t			  period_no2,
							   const std::string &user_uri_mcx2,
							   const std::string &user_id2,
							   const std::string &ssk2,
							   const std::string &rsk2,
							   const std::string &pvt2);

	static bool StoreKeyMaterialsFromCache(std::vector<KeyInfos2> &keyInfos,
										   const std::string		 &userUri,
										   uint8_t				   teeType,
										   int					   mode);

private:
	KmcTeeManager() = delete;
	~KmcTeeManager() = delete;
	KmcTeeManager(const KmcTeeManager &) = delete;
	KmcTeeManager& operator=(const KmcTeeManager&) = delete;
};

} // namespace KMC

#endif // KMC_TEE_STORAGE_H_