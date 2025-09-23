#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
#include "open-source-module/base64.h"
}

#include "LocalDataEncryptUtils.h"
#include "KmcContextManager.h"

namespace KMC {

LocalDataEncrypt& LocalDataEncrypt::GetInstance() {
    static LocalDataEncrypt instance;
    return instance;
}

LocalDataEncrypt::LocalDataEncrypt()
{
#ifndef __ANDROID__
    m_path = KmcContextManager::getInstance().GetConfigPath();
#endif
}

LocalDataEncrypt::~LocalDataEncrypt() {}

#ifndef __ANDROID__
int LocalDataEncrypt::Initialize()
{
    m_primaryKsf = m_path + "/primary.ks";
    m_standbyKsf = m_path + "/standby.ks";

    m_kmcConfig.reset(new KmcConfig());
    if (!m_kmcConfig) {
        kmclog_e(LOG_TAG, "LocalDataEncrypt Init memory malloc failed");
        return KMC_FAIL; // 内存分配失败
    }

    std::memset(m_kmcConfig.get(), 0, sizeof(KmcConfig));

    (void) memcpy(m_kmcConfig->primaryKeyStoreFile, m_primaryKsf.c_str(), m_primaryKsf.length());
    (void) memcpy(m_kmcConfig->standbyKeyStoreFile, m_standbyKsf.c_str(), m_standbyKsf.length());

	m_kmcConfig->domainCount = 8;
	m_kmcConfig->role = 1;
	m_kmcConfig->procLockPerm = 0660;
	m_kmcConfig->sdpAlgId = WSEC_ALGID_AES256_GCM;
	m_kmcConfig->hmacAlgId = WSEC_ALGID_HMAC_SHA512;
	m_kmcConfig->semKey = 0x20161316;

    if (KeInitialize(m_kmcConfig.get()) != KE_ERROR_CODE::KE_RET_SUCCESS) {
        kmclog_e(LOG_TAG, "LocalDataEncrypt Init failed");
        return KMC_FAIL;
    }

    kmclog_i(LOG_TAG, "LocalDataEncrypt Initialized Successfully.");
    return KMC_SUCCESS;
}

int LocalDataEncrypt::Finalize()
{
	int retCode = KeFinalize();

	return retCode;
}
#endif

int LocalDataEncrypt::EncryptByDomain(unsigned int domainID,
                                      const char  *plainText,
                                      int         plainTextLen,
                                      char        **cipherText,
                                      int         &cipherTextLen)
{
#ifdef __ANDROID__
    int returnCode = KMC_FAIL;

    if (!plainText || plainTextLen <= 0) {
        return returnCode;
    }

    std::string plainStr(plainText, plainTextLen);
    std::string cipherStr = encryptByJava(plainStr);

    if (cipherStr.empty()) {
        kmclog_e(LOG_TAG, "EncryptByJava returned empty string");
        return returnCode;
    }

    cipherTextLen = cipherStr.size();
    *cipherText = new (std::nothrow) char[cipherTextLen + 1];
    if (*cipherText == nullptr) {
        kmclog_e(LOG_TAG, "Failed to allocate memory for cipherText");
        return returnCode;
    }

    strcpy(*cipherText, cipherStr.c_str());
    return 0; // 成功
#else
    int returnCode = KMC_FAIL;

    if (!plainText)
        return returnCode;

    *cipherText = NULL;
    cipherTextLen = 0;

    returnCode = ::KeEncryptByDomain(domainID, plainText, plainTextLen, cipherText,
                                  &cipherTextLen);
    if (returnCode != KE_ERROR_CODE::KE_RET_SUCCESS || !cipherText || cipherTextLen <= 0) {
        kmclog_e(LOG_TAG, "LocalDataEncrypt Encrypt error, returnCode:%d", returnCode);
        return returnCode;
    }

    return returnCode;
#endif
}

int LocalDataEncrypt::DecryptByDomain(unsigned int domainID,
                                      const char	*cipherText,
                                      int		  cipherTextLen,
                                      char		  **plainText,
                                      int		 &plainTextLen)
{
#ifdef __ANDROID__
    int returnCode = KMC_FAIL;

    if (!cipherText || cipherTextLen <= 0) {
        return returnCode;
    }

    // 将cipherText转换为std::string
    std::string cipherStr(cipherText, cipherTextLen);

    // 调用Java的decryptByJava方法
    std::string plainStr = decryptByJava(cipherStr);

    if (plainStr.empty()) {
        kmclog_e(LOG_TAG, "DecryptByJava returned empty string");
        return returnCode;
    }

    // 分配内存给plainText
    plainTextLen = plainStr.size();
    *plainText = new (std::nothrow) char[plainTextLen + 1];
    if (*plainText == nullptr) {
        kmclog_e(LOG_TAG, "Failed to allocate memory for plainText");
        return returnCode;
    }

    // 复制解密后的字符串
    strcpy(*plainText, plainStr.c_str());
    return 0; // 成功
#else
    int returnCode = KMC_FAIL;

    if (!cipherText)
        return returnCode;

    *plainText = NULL;
    plainTextLen = 0;

    returnCode = ::KeDecryptByDomain(domainID, cipherText, cipherTextLen,
                                  plainText, &plainTextLen);
    if (returnCode != KE_ERROR_CODE::KE_RET_SUCCESS || !plainText || plainTextLen <= 0) {
        kmclog_e(LOG_TAG, "LocalDataEncrypt Decrypt error, returnCode:%d", returnCode);
        return returnCode;
    }

    return returnCode;
#endif
}

std::string KmcEncryptKeyMaterial::EncryptKeyMaterial(const KeyInfos2& key_info) {
    LocalDataEncrypt& localEncrypt = LocalDataEncrypt::GetInstance();
    // 将密钥材料组合成JSON格式字符串
    std::ostringstream oss;
    oss << "{"
        << "\"ssk\":\"" << key_info.ssk << "\","
        << "\"rsk\":\"" << key_info.rsk << "\","
        << "\"pvt\":\"" << key_info.pvt << "\""
        << "}";

    std::string material_data = oss.str();

    // 使用LocalDataEncrypt加密密钥材料
    char* encrypted_data = nullptr;
    int encrypted_len = 0;

    const unsigned int domain_id = 0;

    int ret = localEncrypt.EncryptByDomain(domain_id, material_data.c_str(),
                                    material_data.length(), &encrypted_data,
                                    encrypted_len);

    if (ret != KMC_SUCCESS || !encrypted_data) {
        kmclog_e(LOG_TAG, "Failed to encrypt key material, error code: %d", ret);
        return "";
    }

    // 将加密后的数据转换为字符串
    std::string result(encrypted_data, encrypted_len);

    // 释放分配的内存
    if (encrypted_data) {
        free(encrypted_data);
    }

    return result;
}

bool KmcEncryptKeyMaterial::DecryptKeyMaterial(const std::string& encrypted_data, KeyInfos2& keyInfos) {
    if (encrypted_data.empty()) {
        kmclog_e(LOG_TAG, "Encrypted data is empty");
        return false;
    }

    LocalDataEncrypt& localEncrypt = LocalDataEncrypt::GetInstance();
    
    // 使用LocalDataEncrypt解密密钥材料
    char* decrypted_data = nullptr;
    int decrypted_len = 0;
    
    const unsigned int domain_id = 0;
    
    int ret = localEncrypt.DecryptByDomain(domain_id, encrypted_data.c_str(),
                                    encrypted_data.length(), &decrypted_data,
                                    decrypted_len);
    
    if (ret != KMC_SUCCESS || !decrypted_data) {
        kmclog_e(LOG_TAG, "Failed to decrypt key material, error code: %d", ret);
        return false;
    }
    
    // 解析JSON格式的密钥材料
    std::string json_data(decrypted_data, decrypted_len);
    
    // 释放分配的内存
    if (decrypted_data) {
        free(decrypted_data);
    }
    
    // 简单的JSON解析
    try {
        // 查找并提取ssk
        size_t ssk_start = json_data.find("\"ssk\":\"") + 7;
        size_t ssk_end = json_data.find("\"", ssk_start);
        if (ssk_start != std::string::npos && ssk_end != std::string::npos) {
            keyInfos.ssk = json_data.substr(ssk_start, ssk_end - ssk_start);
        }
        
        // 查找并提取rsk
        size_t rsk_start = json_data.find("\"rsk\":\"") + 7;
        size_t rsk_end = json_data.find("\"", rsk_start);
        if (rsk_start != std::string::npos && rsk_end != std::string::npos) {
            keyInfos.rsk = json_data.substr(rsk_start, rsk_end - rsk_start);
        }
        
        // 查找并提取pvt
        size_t pvt_start = json_data.find("\"pvt\":\"") + 7;
        size_t pvt_end = json_data.find("\"", pvt_start);
        if (pvt_start != std::string::npos && pvt_end != std::string::npos) {
            keyInfos.pvt = json_data.substr(pvt_start, pvt_end - pvt_start);
        }
        
        kmclog_i(LOG_TAG, "Successfully decrypted key material");
    } catch (const std::exception& e) {
        kmclog_e(LOG_TAG, "Failed to parse decrypted JSON data: %s", e.what());
        keyInfos.init(); // 重置为空
    }
    
    return true;
}

std::string KmcEncryptGmk::EncryptSsvAndRand(const GmkInfo &gmkInfo)
{
    LocalDataEncrypt& localEncrypt = LocalDataEncrypt::GetInstance();
    // 将密钥材料组合成JSON格式字符串
    std::ostringstream oss;
    oss << "{"
        << "\"ssv\":\"" << gmkInfo.ssv << "\","
        << "\"rand\":\"" << gmkInfo.rand << "\","
        << "}";
    
    std::string material_data = oss.str();

    // 使用LocalDataEncrypt加密密钥材料
    char* encrypted_data = nullptr;
    int encrypted_len = 0;
    
    const unsigned int domain_id = 0;

    int ret = localEncrypt.EncryptByDomain(domain_id, material_data.c_str(),
                                    material_data.length(), &encrypted_data,
                                    encrypted_len);

    if (ret != KMC_SUCCESS || !encrypted_data) {
        kmclog_e(LOG_TAG, "Failed to encrypt key material, error code: %d", ret);
        return "";
    }
    
    // 将加密后的数据转换为字符串
    std::string result(encrypted_data, encrypted_len);
    
    // 释放分配的内存
    if (encrypted_data) {
        free(encrypted_data);
    }
    
    return result;
}

std::pair<std::string, std::string> KmcEncryptGmk::DecryptSsvAndRand(const std::string& encrypted_data) {
    std::pair<std::string, std::string> result;
    
    if (encrypted_data.empty()) {
        kmclog_e(LOG_TAG, "Encrypted data is empty");
        return result;
    }

    LocalDataEncrypt& localEncrypt = LocalDataEncrypt::GetInstance();
    
    // 使用LocalDataEncrypt解密密钥材料
    char* decrypted_data = nullptr;
    int decrypted_len = 0;
    
    const unsigned int domain_id = 0;
    
    int ret = localEncrypt.DecryptByDomain(domain_id, encrypted_data.c_str(),
                                    encrypted_data.length(), &decrypted_data,
                                    decrypted_len);
    
    if (ret != KMC_SUCCESS || !decrypted_data) {
        kmclog_e(LOG_TAG, "Failed to decrypt ssv and rand, error code: %d", ret);
        return result;
    }
    
    // 解析JSON格式的数据
    std::string json_data(decrypted_data, decrypted_len);
    
    // 释放分配的内存
    if (decrypted_data) {
        free(decrypted_data);
    }
    
    // 简单的JSON解析
    try {
        // 查找并提取ssv
        size_t ssv_start = json_data.find("\"ssv\":\"") + 7;
        size_t ssv_end = json_data.find("\"", ssv_start);
        if (ssv_start != std::string::npos && ssv_end != std::string::npos) {
            result.first = json_data.substr(ssv_start, ssv_end - ssv_start);
        }
        
        // 查找并提取rand
        size_t rand_start = json_data.find("\"rand\":\"") + 8;
        size_t rand_end = json_data.find("\"", rand_start);
        if (rand_start != std::string::npos && rand_end != std::string::npos) {
            result.second = json_data.substr(rand_start, rand_end - rand_start);
        }
        
        kmclog_i(LOG_TAG, "Successfully decrypted ssv and rand");
    } catch (const std::exception& e) {
        kmclog_e(LOG_TAG, "Failed to parse decrypted JSON data: %s", e.what());
        result.first.clear();
        result.second.clear();
    }
    
    return result;
}

bool AesKeyWrap::wrap(const std::vector<unsigned char> &key,
		  const std::vector<unsigned char> &data,
		  std::vector<unsigned char>		 &output)
{
	// 输入验证
	if (key.empty()) {
		kmclog_e(LOG_TAG, "Key cannot be empty");
		return false;
	}
	if (data.empty()) {
		kmclog_e(LOG_TAG, "Data cannot be empty");
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		kmclog_e(LOG_TAG, "Failed to create EVP_CIPHER_CTX");
		return false;
	}

	// 根据密钥长度选择合适的算法
	const EVP_CIPHER *cipher = selectCipherByKeySize(key.size());
	if (!cipher) {
		kmclog_e(LOG_TAG, "Unsupported key size");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	output.resize(data.size() + 16); // 预留足够空间
	int outLen1 = 0, outLen2 = 0;

	// 初始化加密操作
	if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr)) {
		kmclog_e(LOG_TAG, "EVP_EncryptInit_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// 禁用填充（Key Wrap 通常自己处理数据块）
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	// 更新加密操作
	if (1 !=
		EVP_EncryptUpdate(ctx, output.data(), &outLen1, data.data(),
						  data.size())) {
		kmclog_e(LOG_TAG, "EVP_EncryptUpdate failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// 结束加密操作
	if (1 != EVP_EncryptFinal_ex(ctx, output.data() + outLen1, &outLen2)) {
		kmclog_e(LOG_TAG, "EVP_EncryptFinal_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	int totalOutLen = outLen1 + outLen2;
	output.resize(totalOutLen); // 调整到实际大小
	EVP_CIPHER_CTX_free(ctx);

	return true;
}

bool AesKeyWrap::unwrap(const std::vector<unsigned char> &key,
			const std::vector<unsigned char> &wrappedData,
			std::vector<unsigned char>	   &output)
{
	// 输入验证
	if (key.empty()) {
		kmclog_e(LOG_TAG, "Key cannot be empty");
		return false;
	}
	if (wrappedData.empty()) {
		kmclog_e(LOG_TAG, "Wrapped data cannot be empty");
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		kmclog_e(LOG_TAG, "Failed to create EVP_CIPHER_CTX");
		return false;
	}

    /* Must allow wrap mode, because OpenSSL does nothing in an obvious way */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	// 根据密钥长度选择合适的算法
	const EVP_CIPHER *cipher = selectCipherByKeySize(key.size());
	if (!cipher) {
		kmclog_e(LOG_TAG, "Unsupported key size");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	output.resize(wrappedData.size()); // 预留足够空间
	int outLen1 = 0, outLen2 = 0;

	// 初始化解密操作
	if (1 != EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr)) {
		kmclog_e(LOG_TAG, "EVP_DecryptInit_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	//EVP_CIPHER_CTX_set_padding(ctx, 0);

	// 更新解密操作
	int result = EVP_DecryptUpdate(ctx, output.data(), &outLen1,
								   wrappedData.data(), wrappedData.size());
	if (1 != result) {
		kmclog_e(LOG_TAG, "EVP_DecryptUpdate failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// 结束解密操作
	if (1 != EVP_DecryptFinal_ex(ctx, output.data() + outLen1, &outLen2)) {
		kmclog_e(LOG_TAG, "EVP_DecryptFinal_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	int totalOutLen = outLen1 + outLen2;
	output.resize(totalOutLen); // 调整到实际大小
	EVP_CIPHER_CTX_free(ctx);

	return true;
}

bool AesKeyWrap::hexToBytes(const std::string &hexStr, std::vector<unsigned char> &output)
{
	std::string processedHex = hexStr;

	// 处理连字符"-"（兼容老算法中的盐值格式）
	if (processedHex.find('-') != std::string::npos) {
		std::string temp;
		for (char c : processedHex) {
			if (c != '-') {
				temp += c;
			}
		}
		processedHex = temp;
	}

	// 检查长度是否为偶数
	if (processedHex.length() % 2 != 0) {
		kmclog_e(LOG_TAG,
				 "Hex string must have even length after removing hyphens");
		return false;
	}

	output.clear();
	output.reserve(processedHex.length() / 2);

	for (size_t i = 0; i < processedHex.length(); i += 2) {
		std::string byteString = processedHex.substr(i, 2);
		// 使用stoul将十六进制字符串转换为字节
		unsigned char byte =
				static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
		output.push_back(byte);
	}

	return true;
}

bool AesKeyWrap::bytesToHex(const std::vector<unsigned char> &bytes, std::string &output)
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');

	for (unsigned char byte : bytes) {
		ss << std::setw(2) << static_cast<int>(byte);
	}

	output = ss.str();
	return true;
}

bool AesKeyWrap::wrapHex(const std::string &keyHex,
			 const std::string &dataHex,
			 std::string		 &output)
{
	std::vector<unsigned char> key, data, wrapped;

	if (!hexToBytes(keyHex, key) || !hexToBytes(dataHex, data)) {
		return false;
	}

	if (!wrap(key, data, wrapped)) {
		return false;
	}

	return bytesToHex(wrapped, output);
}

std::string AesKeyWrap::sha256(const std::string &input)
{
	// 创建 EVP_MD_CTX
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    
    if (!ctx) {
        kmclog_e(LOG_TAG,"Failed to create MD context");
        return "";
    }

    // 初始化 SHA-256
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        kmclog_e(LOG_TAG,"Failed to initialize digest");
        return "";
    }

    // 更新数据
    if (EVP_DigestUpdate(ctx.get(), input.c_str(), input.length()) != 1) {
        kmclog_e(LOG_TAG,"Failed to update digest");
        return "";
    }

    // 获取结果（32字节）
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &length) != 1) {
        kmclog_e(LOG_TAG,"Failed to finalize digest");
        return "";
    }

    // 转为十六进制字符串
    std::stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool AesKeyWrap::unwrapHex(const std::string &keyHex,
			   const std::string &wrappedDataHex,
			   std::string	   &output)
{
	std::vector<unsigned char> key, wrappedData, unwrapped;

	if (!hexToBytes(keyHex, key) || !hexToBytes(wrappedDataHex, wrappedData)) {
		return false;
	}

	if (!unwrap(key, wrappedData, unwrapped)) {
		return false;
	}

	return bytesToHex(unwrapped, output);
}

//kms端的加密对应的是带填充的aes密钥封装算法
const EVP_CIPHER *AesKeyWrap::selectCipherByKeySize(size_t keySize)
{
	switch (keySize) {
		case 16:
			return EVP_aes_128_wrap_pad();
		case 24:
			return EVP_aes_192_wrap_pad();
		case 32:
			return EVP_aes_256_wrap_pad();
		default:
			return nullptr;
	}
}

} //namespace KMC