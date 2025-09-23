#include "KmsHttpManger.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <memory>

#ifdef __GNUC__
#include <securec.h>
#endif

#include "KmcContextManager.h"

namespace KMC {


// MemoryBuffer 实现
void MemoryBuffer::Resize(size_t new_size) {
    if (new_size > capacity) {
        std::unique_ptr<char[]> new_memory(new char[new_size]);
        if (memory && size > 0) {
            std::memcpy(new_memory.get(), memory.get(), size);
        }
        memory = std::move(new_memory);
        capacity = new_size;
    }
}

void MemoryBuffer::Append(const void* data, size_t append_size) {
    if (size + append_size + 1 > capacity) {
        Resize((size + append_size + 1) * 2);
    }
    std::memcpy(memory.get() + size, data, append_size);
    size += append_size;
    memory[size] = '\0';
}

// CommHttpManager 实现
CommHttpManager::CommHttpManager(std::string httpsCertPath) : m_httpsCertPath(std::move(httpsCertPath))
                                                            ,m_curlHandle(nullptr)  {
    if (!InitializeCurl()) {
        kmclog_e(LOG_TAG, "Failed to initialize CURL");
    }
}

CommHttpManager::~CommHttpManager() {
    CleanupCurl();
}

bool CommHttpManager::InitializeCurl() {
    curl_global_init(CURL_GLOBAL_ALL);
    m_curlHandle = curl_easy_init();
    if (m_curlHandle) {
        SetupHttpsOptions();
        SetupCertificateVerification();
    }
    return m_curlHandle != nullptr;
}

void CommHttpManager::CleanupCurl() {
    if (m_curlHandle) {
        curl_easy_cleanup(m_curlHandle);
        m_curlHandle = nullptr;
    }
    curl_global_cleanup();
}

void CommHttpManager::SetupHttpsOptions() {
    if (!m_curlHandle) return;
    
    // 启用HTTPS
    curl_easy_setopt(m_curlHandle, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    
    // 设置TLS版本，tls1.2
    curl_easy_setopt(m_curlHandle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    
    // 设置协议（仅HTTPS）
    curl_easy_setopt(m_curlHandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    
    // 禁用信号处理（多线程安全）
    curl_easy_setopt(m_curlHandle, CURLOPT_NOSIGNAL, 1L);
}

void CommHttpManager::SetupCertificateVerification() {
    if (!m_curlHandle) return;
    
    if(m_httpsCertPath.empty())
    {
        // 暂时禁用证书验证，后续需要配置鼎桥和华为认证证书
        curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    else 
    {
        //如果有证书文件，可以这样设置：
        curl_easy_setopt(m_curlHandle, CURLOPT_CAINFO, m_httpsCertPath.c_str());
        curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(m_curlHandle, CURLOPT_SSL_VERIFYHOST, 2L);
    }
}

size_t CommHttpManager::DefaultWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t real_size = size * nmemb;
    auto* buffer = static_cast<MemoryBuffer*>(userp);
    
    if (buffer) {
        buffer->Append(contents, real_size);
        return real_size;
    }
    
    kmclog_e(LOG_TAG, "Invalid memory buffer in write callback");
    return 0;
}

HttpRequestResult CommHttpManager::ExecuteHttpsRequest(const std::string &url,
													   const std::string &authorization_token,
													   const std::string &post_data) {
	HttpRequestResult result;

	if (!m_curlHandle) {
		result.error_message = "Invalid CURL handle";
		result.error_type = KmsErrorType::NETWORK_ERROR;
		kmclog_e(LOG_TAG, "Invalid CURL handle");
		return result;
	}

	struct curl_slist *headers = nullptr;
	MemoryBuffer response_buffer;

	// 设置请求头
	headers = curl_slist_append(headers, "Content-Type: application/xml");

	// 添加Authorization头
	if (!authorization_token.empty()) {
		std::string auth_header = "Authorization: " + authorization_token;
		headers = curl_slist_append(headers, auth_header.c_str());
	}

	// 配置CURL选项
	curl_easy_setopt(m_curlHandle, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(m_curlHandle, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(m_curlHandle, CURLOPT_URL, url.c_str());
	curl_easy_setopt(m_curlHandle, CURLOPT_POSTFIELDS, post_data.c_str());
	curl_easy_setopt(m_curlHandle, CURLOPT_WRITEFUNCTION, DefaultWriteCallback);
	curl_easy_setopt(m_curlHandle, CURLOPT_WRITEDATA, &response_buffer);

	kmclog_i(LOG_TAG, "Sending HTTPS request to: %s", url.c_str());
	kmclog_d(LOG_TAG, "Request body: %s", post_data.c_str());

	curl_easy_setopt(m_curlHandle, CURLOPT_TIMEOUT, 30L);		 // 总超时30秒
	curl_easy_setopt(m_curlHandle, CURLOPT_LOW_SPEED_LIMIT, 1L); // 1字节/秒下限
	curl_easy_setopt(m_curlHandle, CURLOPT_LOW_SPEED_TIME, 60L); // 持续60秒则中断

	// 执行请求 阻塞 todo需要优化下，如果kms一直没回应会一直卡死在这,目前暂时使用超时退出的机制
	CURLcode res = curl_easy_perform(m_curlHandle);

	// 获取响应码
	curl_easy_getinfo(m_curlHandle, CURLINFO_RESPONSE_CODE, &result.response_code);

	if (res == CURLE_OK) {
		result.success = (result.response_code == static_cast<long>(HttpStatusCode::OK));
		result.error_type = MapCurlErrorToKmsError(res, result.response_code);

		if (response_buffer.memory && response_buffer.size > 0) {
			result.response_data = std::string(response_buffer.memory.get(), response_buffer.size);
		}

		kmclog_i(LOG_TAG, "HTTP Response Code: %ld", result.response_code);
		kmclog_d(LOG_TAG, "Response body: %s", result.response_data.c_str());
	} else {
		result.error_type = MapCurlErrorToKmsError(res, result.response_code);
		result.error_message = std::string(curl_easy_strerror(res));
		kmclog_e(LOG_TAG, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
	}

	// 清理资源
	if (headers) {
		curl_slist_free_all(headers);
	}

	return result;
}

KmsErrorType CommHttpManager::MapCurlErrorToKmsError(CURLcode curl_code, long response_code) {
    if (curl_code == CURLE_OK) {
        switch (response_code) {
            case static_cast<long>(HttpStatusCode::OK):
                return KmsErrorType::SUCCESS;
            case static_cast<long>(HttpStatusCode::UNAUTHORIZED):
                return KmsErrorType::AUTH_FAILED;
            case static_cast<long>(HttpStatusCode::FORBIDDEN):
                return KmsErrorType::FORBIDDEN_ERROR;
            case static_cast<long>(HttpStatusCode::SERVICE_UNAVAILABLE):
                return KmsErrorType::SERVER_ERROR;
            default:
                return KmsErrorType::NETWORK_ERROR;
        }
    }
    
    switch (curl_code) {
        case CURLE_OPERATION_TIMEDOUT:
            return KmsErrorType::TIMEOUT_ERROR;
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_PEER_CERTIFICATE:
        case CURLE_SSL_CERTPROBLEM:
            return KmsErrorType::AUTH_FAILED;
        default:
            return KmsErrorType::NETWORK_ERROR;
    }
}

void CommHttpManager::SetWriteCallback(HttpWriteCallback callback) {
    write_callback_ = callback;
}


} //KMC