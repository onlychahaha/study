#ifndef KMSREQUEST_H_
#define KMSREQUEST_H_

#include <memory>
#include <string>
#include <vector>

namespace KMC {

// KMS请求基类
class KmsBaseRequest : public std::enable_shared_from_this<KmsBaseRequest> {
public:
    typedef std::shared_ptr<KmsBaseRequest> ptr;
    
    KmsBaseRequest(const std::string& user_uri, 
                   const std::string& kms_uri,
                   const std::string& client_id,
                   const std::string& time,
                   const std::string& client_req_url);
    
    virtual ~KmsBaseRequest() = default;
    
    KmsBaseRequest(const KmsBaseRequest&) = delete;
    KmsBaseRequest& operator=(const KmsBaseRequest&) = delete;
    
    // 纯虚函数，子类必须实现
    virtual std::string ToXmlString() const = 0;
    
    // 获取请求类型
    virtual std::string GetRequestType() const = 0;

protected:
    std::string m_userUri;
    std::string m_kmsUri;
    std::string m_clientId;
    std::string m_time;
    std::string m_clientReqUrl;
    
    // 公共的XML头部生成方法
    std::string GetXmlHeader() const;
    std::string GetCommonXmlBody() const;
};

// 密钥和证书下载请求类
class KmsInitRequest : public KmsBaseRequest {
public:
    typedef std::shared_ptr<KmsInitRequest> ptr;
    
    KmsInitRequest(const std::string& user_uri, 
                   const std::string& kms_uri,
                   const std::string& client_id,
                   const std::string& time,
                   const std::string& client_req_url);
    
    virtual ~KmsInitRequest() = default;
    
    virtual std::string ToXmlString() const override;
    virtual std::string GetRequestType() const override;
};

// 证书信息结构体
struct CertificateInfo {
    std::string cert_uri;
    std::string kms_uri;
    
    CertificateInfo(const std::string& cert_uri, const std::string& kms_uri)
        : cert_uri(cert_uri), kms_uri(kms_uri) {}
};

// KMS证书请求更新类
class KmsCertUpdateRequest : public KmsBaseRequest {
public:
    typedef std::shared_ptr<KmsCertUpdateRequest> ptr;
    
    KmsCertUpdateRequest(const std::string& user_uri,
                   const std::string& kms_uri,
                   const std::string& client_id,
                   const std::string& time,
                   const std::string& client_req_url);
    
    virtual ~KmsCertUpdateRequest() = default;
    
    void AddCertificate(const std::string& cert_uri, const std::string& kms_uri);
    virtual std::string ToXmlString() const override;
    virtual std::string GetRequestType() const override;
    
private:
    std::vector<CertificateInfo> m_certificateList;
};

} //KMC

#endif  // KMSREQUEST_H_