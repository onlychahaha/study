#ifndef KMSHTTPSLOGIN_H_
#define KMSHTTPSLOGIN_H_

#include "KmsRequest.h"
#include "KmsResponse.h"
#include "KmsHttpManger.h"

#include <memory>
#include <string>
#include <functional>

#ifdef __GNUC__
#include <securec.h>
#endif

namespace KMC {

// KMC配置类
class KmcSdkConfig : public std::enable_shared_from_this<KmcSdkConfig> {
public:
  typedef std::shared_ptr<KmcSdkConfig> ptr;
  KmcSdkConfig() : m_kmsPort(0), m_isInitialized(false) {}
  
  void SetKmsInfo(const std::string& kms_uri, const std::string& kms_ip, 
                  int kms_port) {
    m_kmsUri = kms_uri;
    m_kmsIp = kms_ip;
    m_kmsPort = kms_port;
  }
  
  const std::string& GetKmsUri() const { return m_kmsUri; }
  const std::string& GetKmsIp() const { return m_kmsIp; }
  uint16_t GetKmsPort() const { return m_kmsPort; }
  
  bool IsInitialized() const { return m_isInitialized; }
  void SetInitialized(bool initialized) { m_isInitialized = initialized; }
  
private:
  std::string m_kmsUri;
  std::string m_kmsIp;
  uint16_t m_kmsPort = 0;
  bool m_isInitialized = false;
};

// 请求配置结构体
struct KmsRequestConfig {
    std::string endpoint;
    std::string user_uri;
    std::string token;
    int max_retry_count = 3;
    int retry_delay_ms = 1000;
    
    KmsRequestConfig(const std::string& ep, const std::string& uri, const std::string& tk)
        : endpoint(ep), user_uri(uri), token(tk) {}
};

// KMC通信工具类
class KmcHttpsLogin : public std::enable_shared_from_this<KmcHttpsLogin> {
public:
    typedef std::shared_ptr<KmcHttpsLogin> ptr;
    using WriteCallback = std::function<size_t(void*, size_t, size_t, void*)>;
    
    KmcHttpsLogin();
    ~KmcHttpsLogin();

    KmcHttpsLogin(const KmcHttpsLogin&) = delete;
    KmcHttpsLogin& operator=(const KmcHttpsLogin&) = delete;

    // 初始化KMC
    int InitKmc(const std::string& user_uri, const std::string& kms_uri,
                const std::string& kms_ip, int kms_port);

    // 统一的KMS请求处理方法
    int ProcessKmsRequest(KmsBaseRequest::ptr request, 
                         KmsBaseResponse::ptr response,
                         const KmsRequestConfig& config);

    // 下载证书
    int DoDownloadCert(const std::string& user_uri, const std::string& token);
    
    // 下载用户密钥
    int DoDownloadKey(const std::string& user_uri, const std::string& token);

    // 证书更新查询 needCertUpdate作为传出参数
    int DoCheckCertUpdate(const std::string& user_uri, const std::string& token, bool& needCertUpdate);

private:
    KmcSdkConfig m_config;
    CommHttpManager m_commHttpManager;
    
    // 构建请求URL
    std::string BuildRequestUrl(const std::string& endpoint) const;
    
    // 创建请求对象的工厂方法
    KmsBaseRequest::ptr CreateRequest(const std::string& request_type,
                                     const std::string& user_uri,
                                     const std::string& url);
    
    // 创建响应对象的工厂方法
    KmsBaseResponse::ptr CreateResponse(const std::string& response_type);
    
    // 重试逻辑
    bool ShouldRetry(int error_code) const;
    
    // 处理特定类型的响应
    void HandleCertUpdateResponse(KmsBaseResponse::ptr response);
};

} // namespace KMC

#endif // KMSHTTPSLOGIN_H_