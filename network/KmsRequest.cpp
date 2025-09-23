#include "KmsRequest.h"

#include <iostream>
#include <sstream>

extern "C"{
    #include "utils/common-utils.h"
}

namespace KMC {

// KmsBaseRequest 实现
KmsBaseRequest::KmsBaseRequest(const std::string& user_uri,
                               const std::string& kms_uri,
                               const std::string& client_id,
                               const std::string& time,
                               const std::string& client_req_url)
    : m_userUri(user_uri)
    , m_kmsUri(kms_uri)
    , m_clientId(client_id)
    , m_time(time)
    , m_clientReqUrl(client_req_url) {
}

std::string KmsBaseRequest::GetXmlHeader() const {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
           "<KmsRequest Version=\"1.1.0\" "
           "xmlns=\"urn:3gpp:ns:mcsecKMSInterface:1.0\" "
           "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
           "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldoc\">";
}

std::string KmsBaseRequest::GetCommonXmlBody() const {
    std::ostringstream oss;
    oss << "<UserUri>" << m_userUri << "</UserUri>"
        << "<KmsUri>" << m_kmsUri << "</KmsUri>";
    
    oss << "<ClientId>" << m_clientId << "</ClientId>";
    
    oss << "<Time>" << m_time << "</Time>"
        << "<ClientReqUrl>" << m_clientReqUrl << "</ClientReqUrl>";
        
    return oss.str();
}

// KmsInitRequest 实现
KmsInitRequest::KmsInitRequest(const std::string& user_uri,
                               const std::string& kms_uri,
                               const std::string& client_id,
                               const std::string& time,
                               const std::string& client_req_url)
    : KmsBaseRequest(user_uri, kms_uri, client_id, time, client_req_url) {
}

std::string KmsInitRequest::ToXmlString() const {
    std::string result = GetXmlHeader() + GetCommonXmlBody() + "</KmsRequest>";
    kmclog_i(LOG_TAG, "KmsInitRequest XML: %s", result.c_str());
    return result;
}

std::string KmsInitRequest::GetRequestType() const {
    return "KmsInit";
}

// KmsCertUpdateRequest 实现
KmsCertUpdateRequest::KmsCertUpdateRequest(const std::string& user_uri,
                               const std::string& kms_uri,
                               const std::string& client_id,
                               const std::string& time,
                               const std::string& client_req_url)
    : KmsBaseRequest(user_uri, kms_uri, client_id, time, client_req_url) {
}

void KmsCertUpdateRequest::AddCertificate(const std::string& cert_uri, const std::string& kms_uri) {
    m_certificateList.emplace_back(cert_uri, kms_uri);
}

std::string KmsCertUpdateRequest::ToXmlString() const {
    std::ostringstream oss;
    oss << GetXmlHeader() << GetCommonXmlBody();
    
    // 添加证书列表
    if (!m_certificateList.empty()) {
        oss << "<CertificateList>";
        for (const auto& cert : m_certificateList) {
            oss << "<Certificate>"
                << "<CertURI>" << cert.cert_uri << "</CertURI>"
                << "<KmsURI>" << cert.kms_uri << "</KmsURI>"
                << "</Certificate>";
        }
        oss << "</CertificateList>";
    }
    
    oss << "</KmsRequest>";

    std::string result = oss.str();
    kmclog_i(LOG_TAG, "KmsCertUpdateRequest XML: %s", result.c_str());
    return result;
}

std::string KmsCertUpdateRequest::GetRequestType() const {
    return "KmsCert";
}

} //KMC