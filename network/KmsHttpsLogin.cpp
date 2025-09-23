#include "KmsHttpsLogin.h"

#include <unistd.h>

#include "Commstruct.h"
#include "KmcUtils.h"
#include "CacheManager.h"

extern "C"{
    #include "utils/common-utils.h"
    #include "native-logic.h"
}

namespace KMC {

KmcHttpsLogin::KmcHttpsLogin() : m_config(), m_commHttpManager() {
}

KmcHttpsLogin::~KmcHttpsLogin() {
}

int KmcHttpsLogin::InitKmc(const std::string& user_uri,
                          const std::string& kms_uri,
                          const std::string& kms_ip, 
                          int kms_port) {
    if (user_uri.empty() || kms_uri.empty() || kms_ip.empty() || kms_port == 0) {
        kmclog_e(LOG_TAG, "Invalid parameters for KMC initialization");
        return KMCSDK_FAIL;
    }

    m_config.SetKmsInfo(kms_uri, kms_ip, kms_port);

    if (!m_config.IsInitialized()) {
        m_config.SetInitialized(true);
    }

    return KMCSDK_SUCCESS;
}

std::string KmcHttpsLogin::BuildRequestUrl(const std::string& endpoint) const {
    return "https://" + m_config.GetKmsIp() + ":" +
           KmcUtils::uint64ToString(m_config.GetKmsPort()) + endpoint;
}

KmsBaseRequest::ptr KmcHttpsLogin::CreateRequest(const std::string& request_type,
                                                const std::string& user_uri,
                                                const std::string& url) {
    std::string current_time = KmcUtils::getCurrentTime();
    std::string kms_uri = m_config.GetKmsUri();
    std::string client_id = "";  // 可选字段
    
    if (request_type == "key_prov" || request_type == "cert_prov") {
        return std::make_shared<KmsInitRequest>(user_uri, kms_uri, client_id, current_time, url);
    } else if (request_type == "certupdatequery") {
        return std::make_shared<KmsCertUpdateRequest>(user_uri, kms_uri, client_id, current_time, url);
    }
    
    return nullptr;
}

KmsBaseResponse::ptr KmcHttpsLogin::CreateResponse(const std::string& response_type) {
    if (response_type == "cert_prov") {
        return std::make_shared<KmsCertProvResponse>();
    } else if (response_type == "key_prov") {
        return std::make_shared<KmsKeyProvResponse>();
    } else if (response_type == "certupdatequery") {
        return std::make_shared<KmsCertUpdateResponse>();
    }
    
    return nullptr;
}

bool KmcHttpsLogin::ShouldRetry(int error_code) const {
    return (error_code == KmsErrorType::FORBIDDEN_ERROR || 
            error_code == KmsErrorType::TIMEOUT_ERROR || 
            error_code == KmsErrorType::SERVER_ERROR);
}

int KmcHttpsLogin::ProcessKmsRequest(KmsBaseRequest::ptr request, 
                                    KmsBaseResponse::ptr response,
                                    const KmsRequestConfig& config) {
    if (!request || !response) {
        kmclog_e(LOG_TAG, "Invalid request or response pointer");
        return KMCSDK_FAIL;
    }

    const std::string url = BuildRequestUrl(config.endpoint);
    std::string request_xml = request->ToXmlString();
    
    kmclog_i(LOG_TAG, "Processing %s request to: %s", 
             request->GetRequestType().c_str(), url.c_str());

    int retry_count = 0;
    int result = KMCSDK_FAIL;
    
    do {
        if (retry_count > 0) {
            kmclog_w(LOG_TAG, "Retrying %s request, attempt %d/%d", 
                     request->GetRequestType().c_str(), retry_count + 1, config.max_retry_count + 1);
            usleep(config.retry_delay_ms * 1000); // 转换为微秒
        }

        // 执行HTTP请求
        HttpRequestResult http_result = m_commHttpManager.ExecuteHttpsRequest(url, config.token, request_xml);
        
        if (http_result.success) {
            // 解析响应
            bool parse_success = response->ParseFromXml(http_result.response_data, 
                                                       config.user_uri, 
                                                       OnlineMode::ONLINE);
            
            if (parse_success && response->IsValid()) {
                kmclog_i(LOG_TAG, "%s request successful", request->GetRequestType().c_str());
                
                // 处理特定类型的响应
                if (response->GetResponseType() == "KmsCertUpdate") {
                    HandleCertUpdateResponse(response);
                }
                
                result = KMCSDK_SUCCESS;
                break;
            } else {
                kmclog_e(LOG_TAG, "Failed to parse %s response", response->GetResponseType().c_str());
                result = static_cast<int>(KmsErrorType::PARSE_ERROR);
                break;  // 解析错误通常不需要重试
            }
        } else {
            result = static_cast<int>(http_result.error_type);
            
            // 记录具体的错误信息
            switch (http_result.error_type) {
                case KmsErrorType::AUTH_FAILED:
                    kmclog_e(LOG_TAG, "%s request failed: Authentication failed", request->GetRequestType().c_str());
                    break;
                case KmsErrorType::FORBIDDEN_ERROR:
                    kmclog_e(LOG_TAG, "%s request failed: Forbidden", request->GetRequestType().c_str());
                    break;
                case KmsErrorType::TIMEOUT_ERROR:
                    kmclog_e(LOG_TAG, "%s request failed: Timeout", request->GetRequestType().c_str());
                    break;
                case KmsErrorType::SERVER_ERROR:
                    kmclog_e(LOG_TAG, "%s request failed: Server error", request->GetRequestType().c_str());
                    break;
                default:
                    kmclog_e(LOG_TAG, "%s request failed: %s", 
                             request->GetRequestType().c_str(), http_result.error_message.c_str());
                    break;
            }
        }
        
        retry_count++;
    } while (ShouldRetry(result) && retry_count <= config.max_retry_count);

    if (result != KMCSDK_SUCCESS && retry_count > config.max_retry_count) {
        kmclog_e(LOG_TAG, "%s request failed after %d retries", 
                 request->GetRequestType().c_str(), config.max_retry_count);
    }

    return result;
}

int KmcHttpsLogin::DoDownloadCert(const std::string& user_uri, const std::string& token) {
    if (token.empty() || user_uri.empty()) {
        kmclog_e(LOG_TAG, "Invalid parameters for DoDownloadCert");
        return KMCSDK_FAIL;
    }

    // 创建请求和响应对象
    KmsRequestConfig config("/keymanagement/identity/v1/init", user_uri, token);
    KmsBaseRequest::ptr request = CreateRequest("cert_prov", user_uri, BuildRequestUrl(config.endpoint));
    KmsBaseResponse::ptr response = CreateResponse("cert_prov");
    
    if (!request || !response) {
        kmclog_e(LOG_TAG, "Failed to create request or response objects for cert download");
        return KMCSDK_FAIL;
    }

    int result = ProcessKmsRequest(request, response, config);
    
    if (result == KMCSDK_SUCCESS) {
        auto cert_response = std::dynamic_pointer_cast<KmsCertProvResponse>(response);
        if (cert_response) {
            kmclog_i(LOG_TAG, "Certificate download successful, count: %zu", 
                     cert_response->GetCertInfosList().size());
        }
    }
    
    return result;
}

int KmcHttpsLogin::DoDownloadKey(const std::string& user_uri, const std::string& token) {
    if (token.empty() || user_uri.empty()) {
        kmclog_e(LOG_TAG, "Invalid parameters for DoDownloadKey");
        return KMCSDK_FAIL;
    }

    // 创建请求和响应对象
    KmsRequestConfig config("/keymanagement/identity/v1/keyprov", user_uri, token);
    KmsBaseRequest::ptr request = CreateRequest("key_prov", user_uri, BuildRequestUrl(config.endpoint));
    KmsBaseResponse::ptr response = CreateResponse("key_prov");
    
    if (!request || !response) {
        kmclog_e(LOG_TAG, "Failed to create request or response objects for key download");
        return KMCSDK_FAIL;
    }

    int result = ProcessKmsRequest(request, response, config);
    
    if (result == KMCSDK_SUCCESS) {
        auto key_response = std::dynamic_pointer_cast<KmsKeyProvResponse>(response);
        if (key_response) {
            kmclog_i(LOG_TAG, "Key download successful, count: %zu", 
                     key_response->GetKeyInfosList().size());
        }
    }
    
    return result;
}

int KmcHttpsLogin::DoCheckCertUpdate(const std::string& user_uri, const std::string& token, bool& needCertUpdate) {
    if (token.empty() || user_uri.empty()) {
        kmclog_e(LOG_TAG, "Invalid parameters for DoCheckCertUpdate");
        return KMCSDK_FAIL;
    }

    // 创建请求和响应对象
    KmsRequestConfig config("/keymanagement/identity/v1/certupdatequery", user_uri, token);
    KmsBaseRequest::ptr request = CreateRequest("certupdatequery", user_uri, BuildRequestUrl(config.endpoint));
    KmsBaseResponse::ptr response = CreateResponse("certupdatequery");
    
    auto kmsCertUpdateRequest = std::dynamic_pointer_cast<KmsCertUpdateRequest>(request);
    CacheManager& cacheMgr = CacheManager::GetInstance();
    if(cacheMgr.HasCachedCertificate() && kmsCertUpdateRequest)
    {
        const CertInfos2* cachedCert = cacheMgr.GetCachedCertificate();
        if(cachedCert)
        {
            kmsCertUpdateRequest->AddCertificate(cachedCert->certUri, cachedCert->kmsUri);
        }
    }
    else
    {
        kmclog_e(LOG_TAG, "No cached certificate available for cert update check");
        return KMCSDK_FAIL;
    }

    if (!request || !response) {
        kmclog_e(LOG_TAG, "Failed to create request or response objects for cert update check");
        return KMCSDK_FAIL;
    }

    int result = ProcessKmsRequest(request, response, config);

    if (result == KMCSDK_SUCCESS) {
        auto certUpdate_response = std::dynamic_pointer_cast<KmsCertUpdateResponse>(response);
        if (certUpdate_response) {
            needCertUpdate = certUpdate_response->GetCertUpdateIndication();
        }
    }
    return result;
}

void KmcHttpsLogin::HandleCertUpdateResponse(KmsBaseResponse::ptr response) {
    auto cert_update_response = std::dynamic_pointer_cast<KmsCertUpdateResponse>(response);
    if (cert_update_response && cert_update_response->GetCertUpdateIndication()) {
        kmclog_i(LOG_TAG, "Certificate update is required, triggering certificate download");
        // 这里可以触发证书下载流程
        // DoDownloadCert(cert_update_response->GetUserUri(), /* token */);
    }
}

} // namespace KMC