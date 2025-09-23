#include "KmcUtils.h"

#include <cstring>

#include <algorithm>
#include <memory>
#inlcude <ctime>

#include "Commstruct.h"
#include "common-utils.h"
#include "grp-keying-materials/gms/gms-grp-keying-materials.h"

#include "CacheManager.h"
extern "C"{
    #include "native-logic.h"
}
namespace KMC {

std::string getCurrentTime() {
    // 获取当前系统时间点
    auto now = std::chrono::system_clock::now();
    // 转换为 time_t (UTC 时间)
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);  // Windows 版本, 使用 gmtime_s 获取 UTC 时间
#else
    gmtime_r(&t, &tm);   // POSIX 版本, 使用 gmtime_r 获取 UTC 时间
#endif

    std::ostringstream oss;
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
    oss << buffer; // 输出格式: yyyy-MM-ddTHH:mm:ss

    // 添加固定的时区偏移 "+00:00"
    oss << "+00:00";

    return oss.str();
}

uint64_t KmcUtils::getUnixTimestampSeconds()
{
	// 获取当前时间点与Epoch的时间差（秒）
	auto now = std::chrono::system_clock::now();
	auto duration = now.time_since_epoch();
	return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

std::string KmcUtils::uint64ToString(uint64_t value) {
    std::stringstream ss;
    ss << value;
    return ss.str();
}

void KmcUtils::CertInfosToCertInfos2(const CertInfos& certInfos, CertInfos2& certInfos2) {
    // 转换字符串字段
    certInfos2.version = std::string(certInfos.version);
    certInfos2.certUri = std::string(certInfos.certUri);
    certInfos2.kmsUri = std::string(certInfos.kmsUri);
    certInfos2.validFrom = std::string(certInfos.validFrom);
    certInfos2.validTo = std::string(certInfos.validTo);
    certInfos2.pubEncKey = std::string(certInfos.pubEncKey);
    certInfos2.pubAuthKey = std::string(certInfos.pubAuthKey);

    // 转换数值字段
    certInfos2.userKeyPeriod = static_cast<uint64_t>(strtoull(certInfos.userKeyPeriod, nullptr, 10));
    certInfos2.userKeyOffset = static_cast<uint64_t>(strtoull(certInfos.userKeyOffset, nullptr, 10));
    certInfos2.revoked = (certInfos.revoked != 0);
}

void KmcUtils::CertInfos2ToCertInfos(const CertInfos2& certInfos2, CertInfos& certInfos) {
    // 转换字符串字段
    strncpy(certInfos.version, certInfos2.version.c_str(), VERSION_LEN - 1);
    certInfos.version[VERSION_LEN - 1] = '\0';
    
    strncpy(certInfos.certUri, certInfos2.certUri.c_str(), CERTURL_LEN - 1);
    certInfos.certUri[CERTURL_LEN - 1] = '\0';
    
    strncpy(certInfos.kmsUri, certInfos2.kmsUri.c_str(), KMSURI_LEN - 1);
    certInfos.kmsUri[KMSURI_LEN - 1] = '\0';
    
    strncpy(certInfos.validFrom, certInfos2.validFrom.c_str(), DATE_LEN - 1);
    certInfos.validFrom[DATE_LEN - 1] = '\0';
    
    strncpy(certInfos.validTo, certInfos2.validTo.c_str(), DATE_LEN - 1);
    certInfos.validTo[DATE_LEN - 1] = '\0';
    
    strncpy(certInfos.pubEncKey, certInfos2.pubEncKey.c_str(), PUBENCKEY_LEN - 1);
    certInfos.pubEncKey[PUBENCKEY_LEN - 1] = '\0';
    
    strncpy(certInfos.pubAuthKey, certInfos2.pubAuthKey.c_str(), PUBAUTHKEY_LEN - 1);
    certInfos.pubAuthKey[PUBAUTHKEY_LEN - 1] = '\0';

    // 转换数值字段
    snprintf(certInfos.userKeyPeriod, KEYPERIOD_LEN, "%llu", 
             static_cast<unsigned long long>(certInfos2.userKeyPeriod));
    snprintf(certInfos.userKeyOffset, KEYOFFSET_LEN, "%llu", 
             static_cast<unsigned long long>(certInfos2.userKeyOffset));
    certInfos.revoked = certInfos2.revoked ? 1 : 0;
}

void KmcUtils::KeyInfosToKeyInfos2(const KeyInfos& keyInfos, KeyInfos2& keyInfos2) {
    // 转换字符串字段
    keyInfos2.certUri = std::string(keyInfos.certUri);
    keyInfos2.kmsUri = std::string(keyInfos.kmsUri);
    keyInfos2.userUri = std::string(keyInfos.userUri);
    keyInfos2.userID = std::string(keyInfos.userID);
    keyInfos2.validFrom = std::string(keyInfos.validFrom);
    keyInfos2.validTo = std::string(keyInfos.validTo);
    keyInfos2.ssk = std::string(keyInfos.ssk);
    keyInfos2.rsk = std::string(keyInfos.rsk);
    keyInfos2.pvt = std::string(keyInfos.pvt);

    // 转换数值字段
    keyInfos2.keyPeriodNo = static_cast<uint64_t>(keyInfos.keyPeriodNo);
}

void KmcUtils::KeyInfos2ToKeyInfos(const KeyInfos2& keyInfos2, KeyInfos& keyInfos) {
    // 转换字符串字段
    strncpy(keyInfos.certUri, keyInfos2.certUri.c_str(), CERTURL_LEN - 1);
    keyInfos.certUri[CERTURL_LEN - 1] = '\0';
    
    strncpy(keyInfos.kmsUri, keyInfos2.kmsUri.c_str(), KMSURI_LEN - 1);
    keyInfos.kmsUri[KMSURI_LEN - 1] = '\0';
    
    strncpy(keyInfos.userUri, keyInfos2.userUri.c_str(), USERURI_LEN - 1);
    keyInfos.userUri[USERURI_LEN - 1] = '\0';
    
    strncpy(keyInfos.userID, keyInfos2.userID.c_str(), VERSION_LEN - 1);
    keyInfos.userID[VERSION_LEN - 1] = '\0';
    
    strncpy(keyInfos.validFrom, keyInfos2.validFrom.c_str(), DATE_LEN - 1);
    keyInfos.validFrom[DATE_LEN - 1] = '\0';
    
    strncpy(keyInfos.validTo, keyInfos2.validTo.c_str(), DATE_LEN - 1);
    keyInfos.validTo[DATE_LEN - 1] = '\0';
    
    strncpy(keyInfos.ssk, keyInfos2.ssk.c_str(), SSK_LEN - 1);
    keyInfos.ssk[SSK_LEN - 1] = '\0';
    
    strncpy(keyInfos.rsk, keyInfos2.rsk.c_str(), RSK_LEN - 1);
    keyInfos.rsk[RSK_LEN - 1] = '\0';
    
    strncpy(keyInfos.pvt, keyInfos2.pvt.c_str(), PVT_LEN - 1);
    keyInfos.pvt[PVT_LEN - 1] = '\0';

    // 转换数值字段
    keyInfos.keyPeriodNo = static_cast<int>(keyInfos2.keyPeriodNo);
}

UserKeyMaterialHolder KmcUtils::CreateUserKeyMaterialHolder(const KeyInfos2& keyInfo, kms_cert* kmsCert) {
    return UserKeyMaterialHolder(keyInfo, kmsCert);
}

KmsCertHolder KmcUtils::CreateKmsCertHolder(const CertInfos2& certInfo) {
    return KmsCertHolder(certInfo);
}

GmkInfo KmcUtils::convertGrpKeyingMaterialsToGmkInfo(const grp_keying_materials_t& src) {
    GmkInfo dst;

    // 转换groupId（uint8_t[] -> std::string）
    dst.groupId = std::string(reinterpret_cast<const char*>(src.groupId), 
                            strnlen(reinterpret_cast<const char*>(src.groupId), MAX_MESSAGE_LEN));

    // 转换ssv（uint8_t[] -> std::string）
    std::vector<uint8_t> ssvVec;
    ssvVec.resize(MAX_MESSAGE_LEN);  // 确保有足够的空间
    size_t mikeyLength = cu_encodeBase64(src.ssv, SSV_LEN, reinterpret_cast<char*>(ssvVec.data()));
    dst.ssv = std::string(reinterpret_cast<const char*>(ssvVec.data()), mikeyLength);

    // 转换rand（msg_t -> std::string）
    if (src.rand.len > 0) {
        std::vector<uint8_t> randVec;
        randVec.resize(MAX_MESSAGE_LEN);  // 确保有足够的空间
        size_t randLength = cu_encodeBase64(src.rand.msg, src.rand.len, reinterpret_cast<char*>(randVec.data()));
        dst.rand = std::string(reinterpret_cast<const char*>(randVec.data()), randLength);
    }

    // 转换gmk_id（uint8_t[] -> std::string）
    dst.gmkId = std::string(reinterpret_cast<const char*>(src.gmk_id), 
                           strnlen(reinterpret_cast<const char*>(src.gmk_id), GMK_ID_LEN));

    // 转换guk_id（uint8_t[] -> std::string）
    dst.gukId = std::string(reinterpret_cast<const char*>(src.guk_id), 
                           strnlen(reinterpret_cast<const char*>(src.guk_id), GUK_ID_LEN));

    // 转换activate_time（uint8_t[] -> std::string）
    dst.activateTime = std::string(reinterpret_cast<const char*>(src.activate_time), 
                                  strnlen(reinterpret_cast<const char*>(src.activate_time), GMK_ACTIVATE_TIME_LEN));

    return dst;
}

//gcc  空string，默认一次性最大接受15个字符
    bool KmcUtils::ConvertGmkToGroupMaterials(const GmkInfo& gmk, grp_keying_materials_t* grpMaterials) {

        // 1. 转换 groupId (string -> uint8_t[MAX_MESSAGE_LEN])
        if (!gmk.groupId.empty()) {
            size_t copyLen = std::min(gmk.groupId.size(), sizeof(grpMaterials->groupId));
            memcpy(grpMaterials->groupId, gmk.groupId.c_str(), copyLen);
        }

        // 2. 转换 ssv (string -> uint8_t[SSV_LEN])
        if (!gmk.ssv.empty()) {
            size_t inlen = strlen(gmk.ssv.c_str());  // 获取 Base64 编码字符串的长度
            cu_decodeBase64(gmk.ssv.c_str(), inlen, grpMaterials->ssv);
        }

        // 3. 转换 rand (string -> msg_t)
        if (!gmk.rand.empty()) {
            size_t inlen = strlen(gmk.rand.c_str());  // 获取 Base64 编码字符串的长度
            grpMaterials->rand.len = cu_decodeBase64(gmk.rand.c_str(), inlen, grpMaterials->rand.msg);
        }

        // 4. 转换其他二进制字段（如gmk_id, guk_id等）
        if (!gmk.gmkId.empty()) {
            size_t copyLen = std::min(gmk.gmkId.size(), sizeof(grpMaterials->gmk_id));
            memcpy(grpMaterials->gmk_id, gmk.gmkId.c_str(), copyLen);
        }

        if (!gmk.gukId.empty()) {
            size_t copyLen = std::min(gmk.gukId.size(), sizeof(grpMaterials->guk_id));
            memcpy(grpMaterials->guk_id, gmk.gukId.c_str(), copyLen);
        }

        if (!gmk.activateTime.empty()) {
            size_t copyLen = std::min(gmk.activateTime.size(), sizeof(grpMaterials->activate_time));
            memcpy(grpMaterials->activate_time, gmk.activateTime.c_str(), copyLen);
        }

        return true;
    }

bool KmcUtils::StringToUInt16(const std::string &str, uint16_t &out, int base)
{
	char *end;
	errno = 0;
	unsigned long value = std::strtoul(str.c_str(), &end, base);

	// 检查转换是否成功
	if (errno != 0 || *end != '\0' || value > UINT16_MAX) {
		return false; // 转换失败或越界
	}
	out = static_cast<uint16_t>(value);
	return true;
}


GmkInfo KmcUtils::ParseGmkByGroupMikey(const std::string& userUri, 
                                    const std::string& groupNumber, 
                                    const std::string& grpMikey)
{
    GmkInfo gmk;
	if (grpMikey.empty()) {
		kmclog_e(LOG_TAG, "mikey_message is empty");
        return gmk;
	}
    kmclog_i(LOG_TAG,"KmcUtils::ParseGmkByGroupMikey, userUri:%s", userUri.c_str());

	mikey_sakke_msg_t extractedEccsiSakkeMsg = ExtractPtpEccsiSakkeMsgHeader(grpMikey);
    // uint64_t timeStamp = GetTimeFormMikeyMes(extractedEccsiSakkeMsg);
    uint8_t *uri_mo = extractedEccsiSakkeMsg.idr[0].id_value.msg;
    uint8_t *uri_mt = extractedEccsiSakkeMsg.idr[1].id_value.msg;


    CacheManager& cache_mgr = CacheManager::GetInstance();
	const CertInfos2 *cert = const_cast<CertInfos2*>(cache_mgr.GetCachedCertificate());

	uint8_t* kmsUriFrom = reinterpret_cast<uint8_t*>(const_cast<char*>(cert->certUri.c_str()));

    KeyInfos2 keyInfo;
    cache_mgr.PickupKeyMaterial(grpMikey, userUri, keyInfo);

    uint8_t mikeyMessage[MAX_MESSAGE_LEN] = {0};
    size_t mikeyLength = cu_decodeBase64(grpMikey.c_str(), grpMikey.size(), mikeyMessage);

    uint8_t* groupNumberToUin8 = reinterpret_cast<uint8_t*>(const_cast<char*>(groupNumber.c_str()));

//    const CertInfos2* certInfos2 = cache_mgr.GetCachedCertificate();
//    auto kmsCertHolder = CreateKmsCertHolder(*certInfos2);
//    auto userKeyHolder = CreateUserKeyMaterialHolder(keyInfo, kmsCertHolder.Get());


    KmsCertHolder* kmsCertHolder = cache_mgr.GetKmsCertHolder();
    UserKeyMaterialHolder* userKeyHolder = cache_mgr.GetUserKeyMaterialHolder(userUri, keyInfo.keyPeriodNo);

    uint8_t *userDate = nullptr;
    grp_keying_materials_t groupSessionKeyMaterial;
	extractGrpEccsiSakkeMsg(kmsUriFrom, uri_mo, uri_mt, mikeyMessage,
                            mikeyLength, groupNumberToUin8,
							groupNumber.length(), &groupSessionKeyMaterial,
							kmsCertHolder->Get(), userKeyHolder->Get(), userDate);
 

    gmk = convertGrpKeyingMaterialsToGmkInfo(groupSessionKeyMaterial);
    //明文的内容在外面赋值
	return gmk;
}

mikey_sakke_msg_t KmcUtils::ExtractPtpEccsiSakkeMsgHeader(const std::string& container_base64) {
    char* container_base64_c = const_cast<char*>(container_base64.c_str());

    uint8_t container_c[MAX_MESSAGE_LEN] = {0}; // 存放base64解码后的mikey message
    size_t container_len = cu_decodeBase64(container_base64_c, container_base64.length(), container_c);
    size_t msg_len_without_sign = 0;
    mikey_sakke_msg_t extractedEccsiSakkeMsg = extractEccsiSakkeMsgWithoutVerificationDecryption(container_c, container_len, &msg_len_without_sign);
    return extractedEccsiSakkeMsg;
}


uint64_t KmcUtils::GetTimeFormMikeyMes(mikey_sakke_msg_t extractedEccsiSakkeMsg)
{
    std::vector<uint8_t> extractedMikeyBytes(MAX_MESSAGE_LEN, 0);
    size_t pt = 0;
    // extractedEccsiSakkeMsg.t.ts_value.len == 8
    memcpy(&extractedMikeyBytes[pt], extractedEccsiSakkeMsg.t.ts_value.msg, extractedEccsiSakkeMsg.t.ts_value.len);
    pt += extractedEccsiSakkeMsg.t.ts_value.len;

    extractedMikeyBytes.resize(pt);
    
    if (extractedMikeyBytes.empty()) {
        kmclog_e("CacheManager", "extractMikey failed - extracted bytes is empty");
        return 0;
    }

    // 解析时间戳
    uint64_t timeStamp = 0;
    int len = std::min(static_cast<int>(extractedMikeyBytes.size()), 4);
    
    if (len >= 4) {
        std::vector<uint8_t> timeStampBytes(extractedMikeyBytes.begin(), 
                                           extractedMikeyBytes.begin() + len);
        
        if (IsByteArrayAllZero(timeStampBytes)) {
            timeStamp = 0;
        } else {
            uint64_t secondsFrom1900 = ByteArrayToLong(timeStampBytes);
            timeStamp = secondsFrom1900 - 2208988800L; // 转换为Unix时间戳
        }
    } else {
        timeStamp = 0;
    }
    
    return timeStamp;
}

bool KmcUtils::IsByteArrayAllZero(const std::vector<uint8_t>& bytes) {
    for (uint8_t byte : bytes) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

uint64_t KmcUtils::ByteArrayToLong(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return 0;
    }
    
    uint64_t result = 0;
    size_t len = std::min(bytes.size(), static_cast<size_t>(8)); // 最多处理8字节
    
    // 大端字节序转换
    for (size_t i = 0; i < len; ++i) {
        result = (result << 8) | static_cast<uint64_t>(bytes[i]);
    }
    
    return result;
}

std::chrono::seconds KmcUtils::CalculateNextDownloadInterval(const std::string& validTo)
{
    if (validTo.empty()) {
        // 如果没有有效期信息，默认15m后
        return std::chrono::seconds(15 * 60);
    }
    
    // 解析validTo时间（假设格式为 "YYYY-MM-DDTHH:MM:SS" 或类似格式）
    std::chrono::system_clock::time_point expiryTime = ParseTimeString(validTo);
    std::chrono::system_clock::time_point currentTime = std::chrono::system_clock::now();
    
    // 计算到期前2-3天的随机时间
    std::chrono::system_clock::duration timeUntilExpiry = expiryTime - currentTime;
    int64_t hoursUntilExpiry = std::chrono::duration_cast<std::chrono::hours>(timeUntilExpiry).count();
    int64_t daysUntilExpiry = hoursUntilExpiry / 24;
    
    if (daysUntilExpiry <= 3) {
        // 如果剩余时间小于3天，在剩余时间的前半段随机选择
        int64_t maxSeconds = std::chrono::duration_cast<std::chrono::seconds>(timeUntilExpiry).count() / 2;
        double randomFraction = 0.5 + 0.5 * (rand() / static_cast<double>(RAND_MAX));
        int64_t randomSeconds = static_cast<int64_t>(maxSeconds * randomFraction);
        return std::chrono::seconds(randomSeconds);
    } else {
        // 如果剩余时间超过3天，在到期前2-3天的范围内随机选择
        std::chrono::system_clock::time_point renewStartTime = expiryTime - std::chrono::hours(3 * 24); // 到期前3天
        std::chrono::system_clock::time_point renewEndTime = expiryTime - std::chrono::hours(2 * 24);   // 到期前2天
        
        std::chrono::system_clock::duration renewDuration = renewEndTime - renewStartTime;
        int64_t renewDurationSeconds = std::chrono::duration_cast<std::chrono::seconds>(renewDuration).count();
        int64_t randomOffsetSeconds = static_cast<int64_t>(renewDurationSeconds * (rand() / static_cast<double>(RAND_MAX)));
        std::chrono::seconds randomOffset = std::chrono::seconds(randomOffsetSeconds);
        
        std::chrono::system_clock::time_point nextDownloadTime = renewStartTime + randomOffset;
        std::chrono::system_clock::duration intervalUntilNextDownload = nextDownloadTime - currentTime;
        
        return std::chrono::duration_cast<std::chrono::seconds>(intervalUntilNextDownload);
    }
}

std::chrono::system_clock::time_point KmcUtils::ParseTimeString(const std::string& timeStr)
{
    std::tm tm = {};
    std::istringstream ss(timeStr);
    
    // 使用正确的格式字符串解析包含 'T' 分隔符的 ISO 8601 时间字符串
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    
    if (ss.fail()) {
        kmclog_e(LOG_TAG, "Failed to parse time string: %s", timeStr.c_str());
        return std::chrono::system_clock::time_point{};
    }
    
    // 将 tm 结构体转换为 time_t，mktime 会考虑本地时区
    std::time_t time = std::mktime(&tm);
    
    // 将 time_t 转换为 system_clock::time_point
    std::chrono::system_clock::time_point time_point = std::chrono::system_clock::from_time_t(time);
    return time_point;
}

bool KmcUtils::ParseEncryptedMaterial(const std::string& jsonData, 
                                   CertInfos2& kmsCert, 
                                   std::vector<KeyInfos2>& keyMaterials,
                                   std::string& kmsUri,
                                   std::string& userUri)
{
	// 解析cert部分
	size_t cert_start = jsonData.find("\"cert\":{");
	if (cert_start == std::string::npos) {
		kmclog_e(LOG_TAG, "Certificate section not found in JSON");
		return false;
	}

	// 查找cert部分的结束位置
	size_t cert_end = cert_start + 8; // 跳过 "cert":{
	int	   brace_count = 1;
	while (cert_end < jsonData.length() && brace_count > 0) {
		if (jsonData[cert_end] == '{')
			brace_count++;
		else if (jsonData[cert_end] == '}')
			brace_count--;
		cert_end++;
	}

	std::string cert_section = jsonData.substr(
			cert_start + 7, cert_end - cert_start - 8); // 提取{}内容

	// 解析证书字段
	kmsCert.version = ExtractJsonStringValue(cert_section, "version");
	kmsCert.certUri = ExtractJsonStringValue(cert_section, "certUri");
	kmsCert.kmsUri = ExtractJsonStringValue(cert_section, "kmsUri");
	kmsCert.validFrom = ExtractJsonStringValue(cert_section, "validFrom");

	// 解析数值字段
	std::string userKeyPeriodStr =
			ExtractJsonStringValue(cert_section, "userKeyPeriod");
	if (!userKeyPeriodStr.empty()) {
		kmsCert.userKeyPeriod = std::stoll(userKeyPeriodStr);
	}

	std::string userKeyOffsetStr =
			ExtractJsonStringValue(cert_section, "userKeyOffset");
	if (!userKeyOffsetStr.empty()) {
		kmsCert.userKeyOffset = std::stoll(userKeyOffsetStr);
	}

	std::string revokedStr = ExtractJsonStringValue(cert_section, "revoked");
	kmsCert.revoked = (revokedStr == "true");

	kmsCert.pubEncKey = ExtractJsonStringValue(cert_section, "pubEncKey");
	kmsCert.pubAuthKey = ExtractJsonStringValue(cert_section, "pubAuthKey");

	// 解析keyprov部分
	size_t keyprov_start = jsonData.find("\"keyprov\":{");
	if (keyprov_start == std::string::npos) {
		kmclog_e(LOG_TAG, "Keyprov section not found in JSON");
		return false;
	}

	// 查找keyprov部分的结束位置
	size_t keyprov_end = keyprov_start + 11; // 跳过 "keyprov":{
	brace_count = 1;
	while (keyprov_end < jsonData.length() && brace_count > 0) {
		if (jsonData[keyprov_end] == '{')
			brace_count++;
		else if (jsonData[keyprov_end] == '}')
			brace_count--;
		keyprov_end++;
	}

	std::string keyprov_section = jsonData.substr(
			keyprov_start + 10, keyprov_end - keyprov_start - 11);

	// 创建密钥材料对象
	KeyInfos2 keyMaterial;
	keyMaterial.certUri = ExtractJsonStringValue(keyprov_section, "certUri");
	keyMaterial.kmsUri = ExtractJsonStringValue(keyprov_section, "kmsUri");
	keyMaterial.userUri = ExtractJsonStringValue(keyprov_section, "userUri");
	keyMaterial.userID = ExtractJsonStringValue(keyprov_section, "userId");
	keyMaterial.validFrom =
			ExtractJsonStringValue(keyprov_section, "validFrom");
	keyMaterial.validTo = ExtractJsonStringValue(keyprov_section, "validTo");

	std::string keyPeriodNoStr =
			ExtractJsonStringValue(keyprov_section, "keyPeriodNo");
	if (!keyPeriodNoStr.empty()) {
		// 去掉引号
		if (keyPeriodNoStr.front() == '"')
			keyPeriodNoStr.erase(0, 1);
		if (keyPeriodNoStr.back() == '"')
			keyPeriodNoStr.pop_back();
		keyMaterial.keyPeriodNo = std::stoll(keyPeriodNoStr);
	}

	keyMaterial.rsk = ExtractJsonStringValue(keyprov_section, "userDecryptKey");
	keyMaterial.ssk =
			ExtractJsonStringValue(keyprov_section, "userSigningKeySSK");
	keyMaterial.pvt =
			ExtractJsonStringValue(keyprov_section, "userPubTokenPVT");

	// 设置输出参数
	kmsUri = kmsCert.kmsUri;
	userUri = keyMaterial.userUri;

	keyMaterials.push_back(keyMaterial);

	kmclog_i(LOG_TAG, "Successfully parsed JSON: kmsUri=%s, userUri=%s",
			 kmsUri.c_str(), userUri.c_str());

	return true;
}

std::string KmcUtils::ExtractJsonStringValue(const std::string& json, const std::string& key)
{
    std::string search_key = "\"" + key + "\":";
    size_t key_pos = json.find(search_key);
    if (key_pos == std::string::npos) {
        return "";
    }
    
    size_t value_start = key_pos + search_key.length();
    
    // 跳过空白字符
    while (value_start < json.length() && std::isspace(json[value_start])) {
        value_start++;
    }
    
    if (value_start >= json.length()) {
        return "";
    }
    
    // 处理字符串值（带引号）
    if (json[value_start] == '"') {
        value_start++; // 跳过开始引号
        size_t value_end = value_start;
        while (value_end < json.length() && json[value_end] != '"') {
            // 处理转义字符
            if (json[value_end] == '\\' && value_end + 1 < json.length()) {
                value_end += 2;
            } else {
                value_end++;
            }
        }
        if (value_end < json.length()) {
            return json.substr(value_start, value_end - value_start);
        }
    }
    // 处理数值或布尔值
    else {
        size_t value_end = value_start;
        while (value_end < json.length() && 
               json[value_end] != ',' && 
               json[value_end] != '}' && 
               json[value_end] != ']' &&
               !std::isspace(json[value_end])) {
            value_end++;
        }
        return json.substr(value_start, value_end - value_start);
    }
    
    return "";
}

    std::string KmcUtils::removeMcpttPrefix(std::string dn) {
        std::string tel = "tel:";
        if (dn != "" && dn != " ") {
            std::locale loc;
            std::string dnLower;
            for (char c : dn) {
                dnLower += std::tolower(c, loc);
            }
            size_t pos = dnLower.find(tel);
            if (pos != std::string::npos) {
                dnLower.replace(pos, tel.length(), "");
            }
            return dnLower;
        }
        return dn;
    }

UserKeyMaterialHolder::UserKeyMaterialHolder() {
    Initialize();
}

UserKeyMaterialHolder::UserKeyMaterialHolder(const KeyInfos2& keyInfo, kms_cert* kmsCert) {
    Initialize();
    UpdateFromKeyInfos2(keyInfo, kmsCert);
}

void UserKeyMaterialHolder::Initialize() {
    // 初始化user_key_material结构体所有字段为nullptr和0
    std::memset(&m_material, 0, sizeof(user_key_material));
}

user_key_material* UserKeyMaterialHolder::Get() {
    return &m_material;
}

const user_key_material* UserKeyMaterialHolder::Get() const {
    return &m_material;
}

void UserKeyMaterialHolder::Reset() {
    // 清空所有数据向量
    m_communityData.clear();
    m_dateData.clear();
    m_useridData.clear();
    m_sskData.clear();
    m_rskData.clear();
    m_pvtData.clear();
    m_periodNoData.clear();
    
    // 重新初始化结构体
    Initialize();
}

void UserKeyMaterialHolder::UpdateFromKeyInfos2(const KeyInfos2& keyInfo, kms_cert* kmsCert) {
    // 准备数据
    m_communityData = StringToUint8Array("");
    m_dateData = StringToUint8Array(keyInfo.validFrom);
    m_useridData = StringToUint8Array(keyInfo.userID);
    m_sskData = StringToUint8Array(keyInfo.ssk);
    m_rskData = StringToUint8Array(keyInfo.rsk);
    m_pvtData = StringToUint8Array(keyInfo.pvt);
    m_periodNoData = Uint64ToUint8Array(keyInfo.keyPeriodNo);

    
    // 调用native接口初始化
    setupUserKeyMaterial(
        kmsCert->KmsCertUri,
        m_dateData.empty() ? nullptr : m_dateData.data(),
        m_useridData.empty() ? nullptr : m_useridData.data(),
        m_sskData.empty() ? nullptr : m_sskData.data(),
        m_rskData.empty() ? nullptr : m_rskData.data(),
        m_pvtData.empty() ? nullptr : m_pvtData.data(),
        m_periodNoData.empty() ? nullptr : m_periodNoData.data(),
        &m_material,
        kmsCert
    );
    
    kmclog_i(LOG_TAG, "UserKeyMaterialHolder updated using native setupUserKeyMaterial for user: %s, period: %llu",
             keyInfo.userID.c_str(), keyInfo.keyPeriodNo);
}

std::vector<uint8_t> UserKeyMaterialHolder::StringToUint8Array(const std::string& str) {
    if (str.empty()) {
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> result(str.begin(), str.end());
    result.push_back('\0'); // 添加null终止符
    return result;
}

std::vector<uint8_t> UserKeyMaterialHolder::Uint64ToUint8Array(uint64_t value) {
//    std::vector<uint8_t> result(sizeof(uint64_t));
//    std::memcpy(result.data(), &value, sizeof(uint64_t));
//    return result;
    std::string str = std::to_string(value);
    std::vector<uint8_t> vec(str.begin(), str.end());
    vec.push_back('\0'); // 添加null终止符
    return vec;
}


KmsCertHolder::KmsCertHolder() {
    Initialize();
}

KmsCertHolder::KmsCertHolder(const CertInfos2& certInfo) {
    Initialize();
    UpdateFromCertInfos2(certInfo);
}

void KmsCertHolder::Initialize() {
    std::memset(&m_cert, 0, sizeof(kms_cert));
}

kms_cert* KmsCertHolder::Get() {
    return &m_cert;
}

const kms_cert* KmsCertHolder::Get() const {
    return &m_cert;
}

void KmsCertHolder::Reset() {
    // 清空所有数据向量
    m_communityData.clear();
    m_kmsUriData.clear();
    m_pubAuthKeyData.clear();
    m_pubEncKeyData.clear();
    m_validFromData.clear();
    m_validToData.clear();
    m_periodData.clear();
    m_offsetData.clear();
    
    // 重新初始化结构体
    Initialize();
}

void KmsCertHolder::UpdateFromCertInfos2(const CertInfos2& certInfo) {
    // 准备数据
    m_communityData = StringToUint8Array(certInfo.certUri);
    m_kmsUriData = StringToUint8Array(certInfo.kmsUri);
    m_pubAuthKeyData = StringToUint8Array(certInfo.pubAuthKey);
    m_pubEncKeyData = StringToUint8Array(certInfo.pubEncKey);
    m_validFromData = StringToUint8Array(certInfo.validFrom);
    m_validToData = StringToUint8Array(certInfo.validTo);
    m_periodData = Uint64ToUint8Array(certInfo.userKeyPeriod);
    m_offsetData = Uint64ToUint8Array(certInfo.userKeyOffset);
    
    // 调用native接口初始化
    setupKmsCert(
        m_communityData.empty() ? nullptr : m_communityData.data(),
        m_kmsUriData.empty() ? nullptr : m_kmsUriData.data(),
        m_pubAuthKeyData.empty() ? nullptr : m_pubAuthKeyData.data(),
        m_pubEncKeyData.empty() ? nullptr : m_pubEncKeyData.data(),
        m_validFromData.empty() ? nullptr : m_validFromData.data(),
        m_validToData.empty() ? nullptr : m_validToData.data(),
        m_periodData.empty() ? nullptr : m_periodData.data(),
        m_offsetData.empty() ? nullptr : m_offsetData.data(),
        &m_cert
    );
    
    kmclog_d(LOG_TAG, "KmsCertHolder updated using native setupKmsCert for certificate: %s", 
             certInfo.certUri.c_str());
}

std::vector<uint8_t> KmsCertHolder::StringToUint8Array(const std::string& str) {
    if (str.empty()) {
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> result(str.begin(), str.end());
    result.push_back('\0'); // 添加null终止符
    return result;
}

std::vector<uint8_t> KmsCertHolder::Uint64ToUint8Array(uint64_t value) {
//    std::vector<uint8_t> result(sizeof(uint64_t));
//    std::memcpy(result.data(), &value, sizeof(uint64_t));
    std::string str = std::to_string(value);
    std::vector<uint8_t> vec(str.begin(), str.end());
    vec.push_back('\0'); // 添加null终止符
    return vec;
}

} // KMC namespace