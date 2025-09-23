#ifndef KMC_UTILS_H_
#define KMC_UTILS_H_

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <locale>

#include "Commstruct.h"

extern "C"{
    #include "kmc-core.h"
}

namespace KMC {

class UserKeyMaterialHolder;
class KmsCertHolder;
//工具类
class KmcUtils {
public:
    // 获取当前时间（默认不带毫秒）
    static std::string getCurrentTime();

    static uint64_t getUnixTimestampSeconds();

    static std::string uint64ToString(uint64_t value);

    static void CertInfosToCertInfos2(const CertInfos& certInfos, CertInfos2& certInfos2);

    static void CertInfos2ToCertInfos(const CertInfos2& certInfos2, CertInfos& certInfos);

    static void KeyInfosToKeyInfos2(const KeyInfos& keyInfos, KeyInfos2& keyInfos2);

    static void KeyInfos2ToKeyInfos(const KeyInfos2& keyInfos2, KeyInfos& keyInfos);

    static UserKeyMaterialHolder CreateUserKeyMaterialHolder(const KeyInfos2& keyInfo, kms_cert* kmsCert);
    static KmsCertHolder CreateKmsCertHolder(const CertInfos2& certInfo);
    
    static GmkInfo convertGrpKeyingMaterialsToGmkInfo(const grp_keying_materials_t& materials);

    static bool StringToUInt16(const std::string &str, uint16_t &out, int base = 10);

    static GmkInfo ParseGmkByGroupMikey(const std::string &userUri,
                                 const std::string &groupNumber,
                                 const std::string &grpMikey);

    static bool IsByteArrayAllZero(const std::vector<uint8_t>& bytes);

    static uint64_t ByteArrayToLong(const std::vector<uint8_t>& bytes);

    static uint64_t GetTimeFormMikeyMes(mikey_sakke_msg_t extractedEccsiSakkeMsg);
    
    static mikey_sakke_msg_t ExtractPtpEccsiSakkeMsgHeader(const std::string& container_base64);
    static bool ConvertGmkToGroupMaterials(const GmkInfo &gmk, grp_keying_materials_t *grpMaterials);

    static std::chrono::seconds CalculateNextDownloadInterval(const std::string& validTo);
    
    static std::chrono::system_clock::time_point ParseTimeString(const std::string& timeStr);

	static bool		   ParseEncryptedMaterial(const std::string		&jsonData,
											  CertInfos2			 &kmsCert,
											  std::vector<KeyInfos2> &keyMaterials,
											  std::string			  &kmsUri,
											  std::string			  &userUri);
	static std::string ExtractJsonStringValue(const std::string &json,
											  const std::string &key);
    static std::string removeMcpttPrefix(std::string dn);

private:
    KmcUtils() = delete;
    ~KmcUtils() = delete;

};


class UserKeyMaterialHolder {
public:
    // 默认构造函数
    UserKeyMaterialHolder();
    
    // 从KeyInfos2构造
    explicit UserKeyMaterialHolder(const KeyInfos2& keyInfo, kms_cert* kmsCert);
    
    UserKeyMaterialHolder(const UserKeyMaterialHolder&) = delete;
    UserKeyMaterialHolder& operator=(const UserKeyMaterialHolder&) = delete;
    
    // 允许移动构造和移动赋值
    UserKeyMaterialHolder(UserKeyMaterialHolder&&) = default;
    UserKeyMaterialHolder& operator=(UserKeyMaterialHolder&&) = default;
    
    // 析构函数（自动释放所有内存）
    ~UserKeyMaterialHolder() = default;
    
    // 获取内部user_key_material结构体的指针（用于与现有C代码兼容）
    user_key_material* Get();
    const user_key_material* Get() const;
    
    // 重置所有字段
    void Reset();
    
    // 从KeyInfos2更新数据
    void UpdateFromKeyInfos2(const KeyInfos2& keyInfo, kms_cert* kmsCert);
    
private:
    // user_key_material结构体实例
    user_key_material m_material;
    
    // 存储转换后的数据（避免临时变量被销毁）
    std::vector<uint8_t> m_communityData;
    std::vector<uint8_t> m_dateData;
    std::vector<uint8_t> m_useridData;
    std::vector<uint8_t> m_sskData;
    std::vector<uint8_t> m_rskData;
    std::vector<uint8_t> m_pvtData;
    std::vector<uint8_t> m_periodNoData;
    
    // 初始化方法
    void Initialize();
    
    std::vector<uint8_t> StringToUint8Array(const std::string& str);
    std::vector<uint8_t> Uint64ToUint8Array(uint64_t value);
};

class KmsCertHolder {
public:
    // 默认构造函数
    KmsCertHolder();
    
    // 从CertInfos2构造
    explicit KmsCertHolder(const CertInfos2& certInfo);
    
    // 禁用拷贝构造和拷贝赋值
    KmsCertHolder(const KmsCertHolder&) = delete;
    KmsCertHolder& operator=(const KmsCertHolder&) = delete;
    
    // 允许移动构造和移动赋值
    KmsCertHolder(KmsCertHolder&&) = default;
    KmsCertHolder& operator=(KmsCertHolder&&) = default;
    
    // 析构函数（自动释放所有内存）
    ~KmsCertHolder() = default;
    
    // 获取内部kms_cert结构体的指针
    kms_cert* Get();
    const kms_cert* Get() const;
    
    // 重置所有字段
    void Reset();
    
    // 从CertInfos2更新数据
    void UpdateFromCertInfos2(const CertInfos2& certInfo);
    
private:
    // kms_cert结构体实例
    kms_cert m_cert;
    
    // 存储转换后的数据（避免临时变量被销毁）
    std::vector<uint8_t> m_communityData;
    std::vector<uint8_t> m_kmsUriData;
    std::vector<uint8_t> m_pubAuthKeyData;
    std::vector<uint8_t> m_pubEncKeyData;
    std::vector<uint8_t> m_validFromData;
    std::vector<uint8_t> m_validToData;
    std::vector<uint8_t> m_periodData;
    std::vector<uint8_t> m_offsetData;
    
    // 初始化方法
    void Initialize();
    
    std::vector<uint8_t> StringToUint8Array(const std::string& str);
    std::vector<uint8_t> Uint64ToUint8Array(uint64_t value);
};

} //KMC

#endif //KMC_UTILS_H_