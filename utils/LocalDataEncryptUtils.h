#ifndef LOCAL_DATA_ENCRYPT_UTILS_H_
#define LOCAL_DATA_ENCRYPT_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>

#ifndef __ANDROID__
#include <kmc/ke_cryptoapi.h>
#include <kmc/ke_errcode.h>
#include <kmc/ke_type.h>
#else
#include "JniCallBack.h"
#endif

#include "Commstruct.h"

#define KMC_IV_LEN 12
namespace KMC {

class LocalDataEncrypt{
public:
    // 获取单例实例
    static LocalDataEncrypt& GetInstance();

    LocalDataEncrypt(const LocalDataEncrypt &) = delete;
    LocalDataEncrypt &operator=(const LocalDataEncrypt &) = delete;
    LocalDataEncrypt(LocalDataEncrypt &&) = delete;
    LocalDataEncrypt &operator=(LocalDataEncrypt &&) = delete;

    // 加密接口
    int EncryptByDomain(unsigned int domainID,
                        const char	*plainText,
                        int		  plainTextLen,
                        char		  **cipherText,
                        int		 &cipherTextLen);

    // 解密接口
    int DecryptByDomain(unsigned int domainID,
                        const char	*cipherText,
                        int		  cipherTextLen,
                        char		  **plainText,
                        int		 &plainTextLen);

#ifndef __ANDROID__
    // 初始化接口
    int Initialize();
    // 反初始化接口
    int Finalize();
#endif

private:
    LocalDataEncrypt();
    ~LocalDataEncrypt();

#ifndef __ANDROID__
    std::string m_primaryKsf;
    std::string m_standbyKsf;
    std::string m_path;
    
    using KmcConfigPtr = std::unique_ptr<KmcConfig>;
    KmcConfigPtr m_kmcConfig;
#endif
};

class KmcEncryptKeyMaterial{
public:
    static std::string EncryptKeyMaterial(const KeyInfos2& key_info);
    static bool DecryptKeyMaterial(const std::string& encrypted_data, KeyInfos2& keyInfos);
private:
    KmcEncryptKeyMaterial() = delete;
    ~KmcEncryptKeyMaterial() = delete;
};

class KmcEncryptGmk{
public:
    static std::string EncryptSsvAndRand(const GmkInfo &gmkInfo);
    static std::pair<std::string, std::string> DecryptSsvAndRand(const std::string& encrypted_data);
private:
    KmcEncryptGmk() = delete;
    ~KmcEncryptGmk() = delete;
};

class AesKeyWrap {
public:
    /**
     * 使用 AES Key Wrap with Padding 算法封装数据
     * @param key 加密密钥（二进制格式）
     * @param data 要加密的原始数据（二进制格式）
     * @param output 成功时存放封装后的数据（二进制格式）
     * @return 成功返回 true，失败返回 false
     */
    static bool wrap(const std::vector<unsigned char>& key, 
                    const std::vector<unsigned char>& data,
                    std::vector<unsigned char>& output);

    /**
     * 使用 AES Key Wrap with Padding 算法解封数据
     * @param key 解密密钥（二进制格式）
     * @param wrappedData 已封装的数据（二进制格式）
     * @param output 成功时存放解封后的原始数据（二进制格式）
     * @return 成功返回 true，失败返回 false 
     */
    static bool unwrap(const std::vector<unsigned char>& key, 
                      const std::vector<unsigned char>& wrappedData,
                      std::vector<unsigned char>& output);

    /**
     * 封装数据的便捷方法（十六进制字符串输入输出）
     * @param keyHex 十六进制格式的加密密钥
     * @param dataHex 十六进制格式的原始数据
     * @param output 成功时存放十六进制格式的封装后数据
     * @return 成功返回 true，失败返回 false 
     */
    static bool wrapHex(const std::string& keyHex, const std::string& dataHex, std::string& output);

    /*
        * 计算字符串的 SHA-256 哈希值（十六进制格式）
        * @param input 输入字符串
        * @return 返回输入字符串的 SHA-256 哈希值（十六进制格式）
    */
    static std::string sha256(const std::string& input);

    /**
     * 解封数据的便捷方法（十六进制字符串输入输出）
     * @param keyHex 十六进制格式的解密密钥
     * @param wrappedDataHex 十六进制格式的已封装数据
     * @param output 成功时存放十六进制格式的解封后原始数据
     * @return 成功返回 true，失败返回 false
     */
    static bool unwrapHex(const std::string& keyHex, const std::string& wrappedDataHex, std::string& output);

    /**
     * 十六进制字符串转换为字节数组（按照Java ByteUtils.fromHex实现）
     * 支持处理连字符"-"分隔符
     * @param hexStr 十六进制字符串
     * @param output 成功时存放转换后的字节数组
     * @return 成功返回 true，失败返回 false 
     */
    static bool hexToBytes(const std::string& hexStr, std::vector<unsigned char>& output);

    /**
     * 字节数组转换为十六进制字符串（按照Java ByteUtils.toHex实现）
     * @param bytes 字节数组
     * @param output 成功时存放转换后的十六进制字符串
     * @return 总是返回 true（此操作不会失败）
     */
    static bool bytesToHex(const std::vector<unsigned char>& bytes, std::string& output);

private:
    /**
     * 根据密钥大小选择合适的加密算法
     * @param keySize 密钥大小（字节数）
     * @return 对应的 EVP_CIPHER 指针，无效大小时返回 nullptr
     */
    static const EVP_CIPHER* selectCipherByKeySize(size_t keySize);
};

} //KMC

#endif //LOCAL_DATA_ENCRYPT_UTILS_H_