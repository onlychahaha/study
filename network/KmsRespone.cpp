#include "KmsResponse.h"

#include <cstdlib>
#include <cstring>

#include <string>
#include <sstream>

#include "KmcContextManager.h"
#include "CacheManager.h"
#include "SqliteConnectionPool.h"
#include "kmcTeeStorage.h"
#include "KmcUtils.h"

namespace KMC {

using namespace tinyxml2;

// KmsBaseResponse 实现
const char* KmsBaseResponse::GetElementText(XMLElement* elem) const {
    return (elem && elem->GetText()) ? elem->GetText() : "";
}

bool KmsBaseResponse::ValidateXmlRoot(XMLDocument& doc, const std::string& expected_root) const {
    XMLElement* root = doc.RootElement();
    if (!root) {
        kmclog_e(LOG_TAG, "No root element found");
        return false;
    }

    std::string root_name = root->Name();
    if (root_name.find(expected_root) == std::string::npos) {
        kmclog_e(LOG_TAG, "Invalid root element: %s, expected %s", 
                root_name.c_str(), expected_root.c_str());
        return false;
    }
    return true;
}

bool KmsBaseResponse::ParseCommonFields(XMLElement* root, CommonFields& fields) const {
    for (XMLElement* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string elem_name = child->Name();
        const char* text = GetElementText(child);
        std::string value = text ? text : "";

        // 去除命名空间前缀
        size_t colon_pos = elem_name.find(':');
        if (colon_pos != std::string::npos) {
            elem_name = elem_name.substr(colon_pos + 1);
        }

        if (elem_name == "UserUri") {
            fields.userUri = value;
        } else if (elem_name == "KmsUri") {
            fields.kmsUri = value;
        } else if (elem_name == "Time") {
            fields.time = value;
        } else if (elem_name == "ClientReqUrl") {
            fields.clientReqUrl = value;
        }
    }
    return true;
}

// KmsCertUpdateResponse 实现
KmsCertUpdateResponse::KmsCertUpdateResponse() : m_certUpdateInd(false) {
    m_isValid = false;
}

bool KmsCertUpdateResponse::ParseFromXml(const std::string& xml_data, 
                                        const std::string& userUri, 
                                        OnlineMode mode) {
    if (xml_data.empty()) {
        kmclog_e(LOG_TAG, "Empty XML data for KmsCertUpdateResponse");
        return false;
    }

    kmclog_i(LOG_TAG, "Parsing KmsCertUpdateResponse XML");
    
    XMLDocument doc;
    XMLError result = doc.Parse(xml_data.c_str());
    if (result != XML_SUCCESS) {
        kmclog_e(LOG_TAG, "Failed to parse XML: %s", doc.ErrorStr());
        return false;
    }

    if (!ValidateXmlRoot(doc)) {
        return false;
    }

    XMLElement* root = doc.RootElement();
    
    // 解析公共字段
    CommonFields common;
    ParseCommonFields(root, common);
    
    m_userUri = common.userUri;
    m_kmsUri = common.kmsUri;
    m_time = common.time;
    m_clientReqUrl = common.clientReqUrl;

    // 解析 CertUpdateInd 字段
    for (XMLElement* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string elem_name = child->Name();
        const char* text = GetElementText(child);
        std::string value = text ? text : "";

        // 去除命名空间前缀
        size_t colon_pos = elem_name.find(':');
        if (colon_pos != std::string::npos) {
            elem_name = elem_name.substr(colon_pos + 1);
        }

        if (elem_name == "CertUpdateInd") {
            m_certUpdateInd = (value == "true" || value == "1");
            kmclog_d(LOG_TAG, "CertUpdateInd: %s -> %s", 
                    value.c_str(), m_certUpdateInd ? "true" : "false");
            break;
        }
    }

    m_isValid = true;
    kmclog_i(LOG_TAG, "Successfully parsed KmsCertUpdateResponse - CertUpdateInd: %s", 
            m_certUpdateInd ? "true" : "false");
    
    return m_isValid;
}

void KmsCertUpdateResponse::Clear() {
    m_userUri.clear();
    m_kmsUri.clear();
    m_time.clear();
    m_clientReqUrl.clear();
    m_certUpdateInd = false;
    m_isValid = false;
}

// 证书反序列化 实现
KmsCertProvResponse::KmsCertProvResponse() {
    m_isValid = false;
}

KmsCertProvResponse::~KmsCertProvResponse() {
    Clear();
}

bool KmsCertProvResponse::ParseFromXml(const std::string& xml_data, const std::string& userUri, OnlineMode mode) {
    if (xml_data.empty()) {
        kmclog_e(LOG_TAG, "Empty XML data for KmsCertProvResponse");
        return false;
    }

    kmclog_i(LOG_TAG, "Parsing KmsCertProvResponse XML");
    
    XMLDocument doc;
    XMLError result = doc.Parse(xml_data.c_str());
    if (result != XML_SUCCESS) {
        kmclog_e(LOG_TAG, "Failed to parse XML: %s", doc.ErrorStr());
        return false;
    }

	if (!ValidateXmlRoot(doc)) {
		return false;
	}

	// 获取根节点 KmsResponse 
    XMLElement* root = doc.RootElement();
    if (!root) {
        kmclog_e(LOG_TAG, "No root element found");
        return false;
    }

    // 检查根节点名称
    std::string root_name = root->Name();
    if (root_name.find("KmsResponse") == std::string::npos) {
        kmclog_e(LOG_TAG, "Invalid root element: %s, expected KmsResponse", root_name.c_str());
        return false;
    }

    // 查找 KmsMessage -> KmsInit -> KmsCertificate 路径
    XMLElement* kms_message = nullptr;
    XMLElement* kms_init = nullptr;
    XMLElement* cert_elem = nullptr;

    for (XMLElement* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string elem_name = child->Name();
        if (elem_name.find("KmsMessage") != std::string::npos) {
            kms_message = child;
            break;
        }
    }

    if (!kms_message) {
        kmclog_e(LOG_TAG, "KmsMessage element not found");
        return false;
    }

    for (XMLElement* child = kms_message->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string child_name = child->Name();
        if (child_name.find("KmsInit") != std::string::npos) {
            kms_init = child;
            break;
        }
    }

    if (!kms_init) {
        kmclog_e(LOG_TAG, "KmsInit element not found");
        return false;
    }

    for (XMLElement* child = kms_init->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string cert_name = child->Name();
        if (cert_name.find("KmsCertificate") != std::string::npos) {
            cert_elem = child;
            break;
        }
    }

    if (!cert_elem) {
        kmclog_e(LOG_TAG, "KmsCertificate element not found");
        return false;
    }

    CertInfos2 cert_info = {};  // 初始化为零

    // 解析版本信息
    const char *version = cert_elem->Attribute("Version");
    if (version) {
        cert_info.version = version;
    } else {
        cert_info.version = "1.0.0";
    }

    // 解析Role属性
    const char *role = cert_elem->Attribute("Role");
    if (role) {
        kmclog_d(LOG_TAG, "Certificate - Role: %s", role);
    }

    for (XMLElement* field_elem = cert_elem->FirstChildElement(); field_elem; field_elem = field_elem->NextSiblingElement()) {
        std::string field_name = field_elem->Name();
        const char* text = GetElementText(field_elem);
        std::string value = text ? text : "";

        // 去除命名空间前缀进行匹配
        size_t colon_pos = field_name.find(':');
        if (colon_pos != std::string::npos) {
            field_name = field_name.substr(colon_pos + 1);
        }

        if (field_name == "CertUri") {
            cert_info.certUri = value;
            kmclog_d(LOG_TAG, "Certificate - CertUri: %s", value.c_str());
        } else if (field_name == "KmsUri") {
            cert_info.kmsUri = value;
            kmclog_d(LOG_TAG, "Certificate - KmsUri: %s", value.c_str());
        } else if (field_name == "ValidFrom") {
            cert_info.validFrom = value;
            kmclog_d(LOG_TAG, "Certificate - ValidFrom: %s", value.c_str());
        } else if (field_name == "ValidTo") {
            cert_info.validTo = value;
            kmclog_d(LOG_TAG, "Certificate - ValidTo: %s", value.c_str());
        } else if (field_name == "PubEncKey") {
            cert_info.pubEncKey = value;
            kmclog_d(LOG_TAG, "Certificate - PubEncKey: %s", value.c_str());
        } else if (field_name == "PubAuthKey") {
            cert_info.pubAuthKey = value;
            kmclog_d(LOG_TAG, "Certificate - PubAuthKey: %s", value.c_str());
        } else if (field_name == "UserKeyPeriod") {
            if (!value.empty()) {
                cert_info.userKeyPeriod = static_cast<uint64_t>(strtoull(value.c_str(), nullptr, 10));
                kmclog_d(LOG_TAG, "Certificate - UserKeyPeriod: %s -> %llu", value.c_str(), cert_info.userKeyPeriod);
            }
        } else if (field_name == "UserKeyOffset") {
            if (!value.empty()) {
                cert_info.userKeyOffset = static_cast<uint64_t>(strtoull(value.c_str(), nullptr, 10));
                kmclog_d(LOG_TAG, "Certificate - UserKeyOffset: %s -> %llu", value.c_str(), cert_info.userKeyOffset);
            }
        } else if (field_name == "Revoked") {
            cert_info.revoked = !(value == "false");
            kmclog_d(LOG_TAG, "Certificate - Revoked: %s", value.c_str());
        } else if (field_name == "UserIdFormat" || field_name == "ParameterSet") {
            // 忽略这个字段
            kmclog_d(LOG_TAG, "Certificate - %s: %s", field_name.c_str(), value.c_str());
        }
    }

    m_certInfosList.push_back(cert_info);

	// 更新缓存
    CacheManager& cache_mgr = CacheManager::GetInstance();
    bool cache_updated = cache_mgr.TryUpdateCertificateCache(cert_info);

    SqliteDatabase sqliteDb;
	uint8_t teeType = KmcContextManager::getInstance().GetTee();
	if (teeType != KMC_TEE_TYPE::KMC_NO_TEE) {
		KmcTeeManager::StoreCert(
				teeType, userUri, OnlineMode::ONLINE, cert_info.version,
				cert_info.certUri, cert_info.kmsUri, "", cert_info.validFrom,
				cert_info.validTo, cert_info.revoked, cert_info.userKeyPeriod,
				cert_info.userKeyOffset, "", cert_info.pubEncKey,
				cert_info.pubAuthKey, "");
        kmclog_i(LOG_TAG,
                         "Successfully stored certificate to Tee");
        //开启tee了，就要把sqlite3本地里面的数据清完，保证一致性
        if (sqliteDb.IsAvailable())
        {
            	sqliteDb.ClearCertTable();
				sqliteDb.ClearKeyTable();
                kmclog_i(LOG_TAG, "cert and key clear successfully For Tee");
        }
	} else {
		// 使用连接池获取数据库连接并存储证书信息
		if (sqliteDb.IsAvailable()) {
			if (cache_updated) {
				sqliteDb.ClearCertTable();
				sqliteDb.ClearKeyTable();
				kmclog_i(LOG_TAG, "Certificate cache updated successfully");
			}
			if (sqliteDb.InsertCertInfo(cert_info, mode)) {
				kmclog_i(LOG_TAG,
						 "Successfully stored certificate to database");
			} else {
				kmclog_w(LOG_TAG, "Failed to store certificate to database");
			}
		} else {
			kmclog_w(LOG_TAG, "Database not available, certificate not stored");
		}
	}

	m_isValid = !m_certInfosList.empty();
    kmclog_i(LOG_TAG, "Successfully parsed certificate");
    return m_isValid;
}

void KmsCertProvResponse::Clear() {
    m_certInfosList.clear();
    m_isValid = false;
}

// 密钥反序列化 实现
KmsKeyProvResponse::KmsKeyProvResponse() {
    m_isValid = false;
}

KmsKeyProvResponse::~KmsKeyProvResponse() {
    Clear();
}

bool KmsKeyProvResponse::ParseFromXml(const std::string &xml_data, const std::string& userUri, OnlineMode mode) {
    if (xml_data.empty()) {
        kmclog_e(LOG_TAG, "Empty XML data for KmsKeyProvResponse");
        return false;
    }

    kmclog_i(LOG_TAG, "Parsing KmsKeyProvResponse XML");
    
    XMLDocument doc;
    XMLError result = doc.Parse(xml_data.c_str());
    if (result != XML_SUCCESS) {
        kmclog_e(LOG_TAG, "Failed to parse XML: %s", doc.ErrorStr());
        return false;
    }

    if (!ValidateXmlRoot(doc)) {
        return false;
    }

    // 获取根节点 KmsResponse
    XMLElement* root = doc.RootElement();
    if (!root) {
        kmclog_e(LOG_TAG, "No root element found");
        return false;
    }

    // 检查根节点名称
    std::string root_name = root->Name();
    if (root_name.find("KmsResponse") == std::string::npos) {
        kmclog_e(LOG_TAG, "Invalid root element: %s, expected KmsResponse", root_name.c_str());
        return false;
    }

    // 查找 KmsMessage -> KmsKeyProv 路径
    XMLElement* kms_message = nullptr;
    XMLElement* kms_key_prov = nullptr;

    for (XMLElement* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string child_name = child->Name();
        if (child_name.find("KmsMessage") != std::string::npos) {
            kms_message = child;
            break;
        }
    }

    if (!kms_message) {
        kmclog_e(LOG_TAG, "KmsMessage element not found");
        return false;
    }

    for (XMLElement* child = kms_message->FirstChildElement(); child; child = child->NextSiblingElement()) {
        std::string child_name = child->Name();
        if (child_name.find("KmsKeyProv") != std::string::npos) {
            kms_key_prov = child;
            break;
        }
    }

    if (!kms_key_prov) {
        kmclog_e(LOG_TAG, "KmsKeyProv element not found");
        return false;
    }

    // 解析所有密钥集（可能有多个）
    int key_count = 0;
    uint8_t teeType = KmcContextManager::getInstance().GetTee();
    
    for (XMLElement* key_elem = kms_key_prov->FirstChildElement(); key_elem; key_elem = key_elem->NextSiblingElement()) {
        std::string key_name = key_elem->Name();
        if (key_name.find("KmsKeySet") == std::string::npos) {
            continue;
        }

        KeyInfos2 key_info = {}; // 初始化为零

        // 一次遍历解析所有字段
        for (XMLElement* field_elem = key_elem->FirstChildElement(); field_elem; field_elem = field_elem->NextSiblingElement()) {
            std::string field_name = field_elem->Name();
            const char* text = GetElementText(field_elem);
            std::string value = text ? text : "";

            // 去除命名空间前缀进行匹配
            size_t colon_pos = field_name.find(':');
            if (colon_pos != std::string::npos) {
                field_name = field_name.substr(colon_pos + 1);
            }

            if (field_name == "CertUri") {
                key_info.certUri = value;
                kmclog_d(LOG_TAG, "Key set %d - CertUri: %s", key_count, value.c_str());
            } else if (field_name == "KmsUri") {
                key_info.kmsUri = value;
                kmclog_d(LOG_TAG, "Key set %d - KmsUri: %s", key_count, value.c_str());
            } else if (field_name == "UserUri") {
                key_info.userUri = value;
                kmclog_d(LOG_TAG, "Key set %d - UserUri: %s", key_count, value.c_str());
            } else if (field_name == "UserID") {
                key_info.userID = value;
                kmclog_d(LOG_TAG, "Key set %d - UserID: %s", key_count, value.c_str());
            } else if (field_name == "ValidFrom") {
                key_info.validFrom = value;
                kmclog_d(LOG_TAG, "Key set %d - ValidFrom: %s", key_count, value.c_str());
            } else if (field_name == "ValidTo") {
                key_info.validTo = value;
                kmclog_d(LOG_TAG, "Key set %d - ValidTo: %s", key_count, value.c_str());
            } else if (field_name == "UserSigningKeySSK") {
                key_info.ssk = value;
                kmclog_d(LOG_TAG, "Key set %d - UserSigningKeySSK: %s", key_count, value.c_str());
            } else if (field_name == "UserDecryptKey") {
                key_info.rsk = value;
                kmclog_d(LOG_TAG, "Key set %d - UserDecryptKey: %s", key_count, value.c_str());
            } else if (field_name == "UserPubTokenPVT") {
                key_info.pvt = value;
                kmclog_d(LOG_TAG, "Key set %d - UserPubTokenPVT: %s", key_count, value.c_str());
            } else if (field_name == "KeyPeriodNo") {
                if (!value.empty()) {
                    key_info.keyPeriodNo = static_cast<uint64_t>(strtoull(value.c_str(), nullptr, 10));
                    kmclog_d(LOG_TAG, "Key set %d - KeyPeriodNo: %s -> %llu", key_count, value.c_str(), key_info.keyPeriodNo);
                }
            } else if (field_name == "Revoked") {
                // 暂不处理 Revoked字段
                kmclog_d(LOG_TAG, "Key set %d - Revoked: %s", key_count, value.c_str());
            }
        }

        m_keyInfosList.push_back(key_info);
        
        // 更新缓存
        CacheManager& cache_mgr = CacheManager::GetInstance();
        bool cache_updated = cache_mgr.TryUpdateKeyCache(key_info);

        //开启了tee，解析完在存储
		if (teeType != KMC_TEE_TYPE::KMC_NO_TEE) 
        {
            continue;
		} 
        else {
			SqliteDatabase sqliteDb;
			if (sqliteDb.IsAvailable()) {
				if (cache_updated) {
					kmclog_i(LOG_TAG,
							 "Key cache updated successfully for key set %d",
							 key_count);
					sqliteDb.DeleteKeyInfo(key_info.userUri,
										   key_info.keyPeriodNo);//这里逻辑用个数据库应增加个更新方法
				}
				std::string encrypted_material =
						KmcEncryptKeyMaterial::EncryptKeyMaterial(key_info);
				if (!encrypted_material.empty()) {
					if (sqliteDb.InsertKeyInfo(key_info, mode,
											   encrypted_material)) {
						kmclog_i(LOG_TAG,
								 "Successfully stored encrypted key material "
								 "%d to database",
								 key_count);
					} else {
						kmclog_w(LOG_TAG,
								 "Failed to store key material %d to database",
								 key_count);
					}
				} else {
					kmclog_e(LOG_TAG, "Failed to encrypt key material %d",
							 key_count);
				}
			} else {
				kmclog_w(LOG_TAG,
						 "Database not available, key material %d not stored",
						 key_count);
			}
		}

		kmclog_i(LOG_TAG, "Successfully parsed key set %d", key_count);
        key_count++;
    }
    
    //开启了tee，解析完了再存储
	if (teeType != KMC_TEE_TYPE::KMC_NO_TEE) {
		if (!KmcTeeManager::StoreKeyMaterialsFromCache(m_keyInfosList, userUri, teeType,
									   mode)) {
			kmclog_e(LOG_TAG, "Tee Storage failed");
			return false;
		}
        kmclog_i(LOG_TAG,
                         "Successfully stored all key sets to Tee");
	}

    //密钥更新，需要同步更新gmk
    parseAndSaveGmkIfNeed(userUri);

	m_isValid = !m_keyInfosList.empty();
	kmclog_i(LOG_TAG, "Successfully parsed %zu key sets",
			 m_keyInfosList.size());
	return m_isValid;
}

void KmsKeyProvResponse::Clear() {
    m_keyInfosList.clear();
    m_isValid = false;
}

void KmsKeyProvResponse::parseAndSaveGmk(const GmkInfo& gmkInfo, const std::string &gmkMikey) {
    GmkInfo parsedGmk = KmcUtils::ParseGmkByGroupMikey(gmkInfo.userUri, gmkInfo.groupId, gmkMikey);

    std::string EncryptData = KmcEncryptGmk::EncryptSsvAndRand(parsedGmk);
    SqliteDatabase sqliteDb;
    bool isSuccess = false;
    if (sqliteDb.IsAvailable()) {
        isSuccess = sqliteDb.InsertGmkInfo(parsedGmk, EncryptData);
    }

    //删除对应的rawgmk
    if(isSuccess)
    {
        sqliteDb.DeleteRawGmkInfo(gmkInfo.userUri, gmkInfo.groupId, gmkInfo.eTag);
    }
}

void KmsKeyProvResponse::parseAndSaveGmkIfNeed(const std::string& userUri) {
    SqliteDatabase sqliteDb;
    std::vector<GmkInfo> gmk_infos;
    if (sqliteDb.IsAvailable()) {
        if(!sqliteDb.QueryGmkInfoByUser(userUri, gmk_infos))
        {
            kmclog_e(LOG_TAG, "parseAndSaveGmkIfNeed, QueryGmkInfoByUser failed.");
            return;
        }
    }

    if(gmk_infos.empty()) {
        kmclog_i(LOG_TAG, "parseAndSaveGmkIfNeed, no gmk for user: %s", userUri.c_str());
        return;
    }
    else{
        for(const auto& gmk_info : gmk_infos) {
            RawGmkInfo rawGmkinfo;
            sqliteDb.QueryRawGmkInfo(userUri, gmk_info.groupId, gmk_info.eTag, rawGmkinfo);
            parseAndSaveGmk(gmk_info, rawGmkinfo.gmkMikey);
        }
    }
}

} //KMC