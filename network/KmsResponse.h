#ifndef KMSRESPONSE_H_
#define KMSRESPONSE_H_

#include <string>
#include <vector>
#include <memory>

#include <tinyxml2/tinyxml2.h>

#include "LocalDataEncryptUtils.h"
#include "Sqlite3Manager.h"

namespace KMC {

// 响应基类 - 抽象所有KMS响应的公共行为
class KmsBaseResponse : public std::enable_shared_from_this<KmsBaseResponse> {
public:
    typedef std::shared_ptr<KmsBaseResponse> ptr;
    
    KmsBaseResponse() : m_isValid(false) {}
    virtual ~KmsBaseResponse() = default;
    
    // 纯虚函数，子类必须实现
    virtual bool ParseFromXml(const std::string& xml_data, 
                             const std::string& userUri, 
                             OnlineMode mode = OnlineMode::ONLINE) = 0;
    
    // 获取响应类型
    virtual std::string GetResponseType() const = 0;
    
    // 清理数据
    virtual void Clear() = 0;
    
    // 检查是否有效
    virtual bool IsValid() const { return m_isValid; }

protected:
    bool m_isValid;
    
    // 公共的XML解析辅助方法
    const char* GetElementText(tinyxml2::XMLElement* elem) const;
    bool ValidateXmlRoot(tinyxml2::XMLDocument& doc, const std::string& expected_root = "KmsResponse") const;
    
    // 解析公共字段
    struct CommonFields {
        std::string userUri;
        std::string kmsUri;
        std::string time;
        std::string clientReqUrl;
    };
    
    bool ParseCommonFields(tinyxml2::XMLElement* root, CommonFields& fields) const;
};

// 证书刷新请求响应类
class KmsCertUpdateResponse : public KmsBaseResponse {
public:
    typedef std::shared_ptr<KmsCertUpdateResponse> ptr;
    
    KmsCertUpdateResponse();
    virtual ~KmsCertUpdateResponse() = default;
    
    virtual bool ParseFromXml(const std::string& xml_data, 
                             const std::string& userUri, 
                             OnlineMode mode = OnlineMode::ONLINE) override;
    
    virtual std::string GetResponseType() const override { return "KmsCertUpdate"; }
    
    virtual void Clear() override;
    
    // 获取证书更新指示
    bool GetCertUpdateIndication() const { return m_certUpdateInd; }
    
    // 获取公共字段
    const std::string& GetUserUri() const { return m_userUri; }
    const std::string& GetKmsUri() const { return m_kmsUri; }
    const std::string& GetTime() const { return m_time; }
    const std::string& GetClientReqUrl() const { return m_clientReqUrl; }

private:
    std::string m_userUri;
    std::string m_kmsUri;
    std::string m_time;
    std::string m_clientReqUrl;
    bool m_certUpdateInd;
};

// 证书供应响应类
class KmsCertProvResponse : public KmsBaseResponse {
public:
    typedef std::shared_ptr<KmsCertProvResponse> ptr;
    
    KmsCertProvResponse();
    virtual ~KmsCertProvResponse();

    virtual bool ParseFromXml(const std::string& xml_data, 
                             const std::string& userUri, 
                             OnlineMode mode = OnlineMode::ONLINE) override;
    
    virtual std::string GetResponseType() const override { return "KmsCertProv"; }
    
    virtual void Clear() override;

    const std::vector<CertInfos2>& GetCertInfosList() const { return m_certInfosList; }

private:
    std::vector<CertInfos2> m_certInfosList;
};

// 密钥供应响应类
class KmsKeyProvResponse : public KmsBaseResponse {
public:
    typedef std::shared_ptr<KmsKeyProvResponse> ptr;
    
    KmsKeyProvResponse();
    virtual ~KmsKeyProvResponse();

    virtual bool ParseFromXml(const std::string& xml_data, 
                             const std::string& userUri, 
                             OnlineMode mode = OnlineMode::ONLINE) override;
    
    virtual std::string GetResponseType() const override { return "KmsKeyProv"; }
    
    virtual void Clear() override;

    const std::vector<KeyInfos2>& GetKeyInfosList() const { return m_keyInfosList; }
    
private:
    void parseAndSaveGmkIfNeed(const std::string& userUri);
    void parseAndSaveGmk(const GmkInfo& gmkInfo, const std::string& gmkMikey);
    std::vector<KeyInfos2> m_keyInfosList;
};

} // namespace KMC

#endif // KMSRESPONSE_H_