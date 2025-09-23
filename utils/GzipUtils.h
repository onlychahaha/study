#ifndef GZIP_UTILS_H
#define GZIP_UTILS_H

#include <vector>
#include <string>
#include <cstdint>

namespace KMC {

/**
 * @brief Gzip压缩解压缩工具类
 * 用于对密钥和证书材料进行压缩，减少存储空间
 */
class GzipUtils {
public:
    /**
     * @brief 压缩数据
     * @param input 待压缩的数据
     * @param output 压缩后的数据
     * @return true 压缩成功，false 压缩失败
     */
    static bool Compress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
    
    /**
     * @brief 压缩字符串数据
     * @param input 待压缩的字符串
     * @param output 压缩后的数据
     * @return true 压缩成功，false 压缩失败
     */
    static bool Compress(const std::string& input, std::vector<uint8_t>& output);
    
    /**
     * @brief 解压缩数据
     * @param input 待解压的数据
     * @param output 解压后的数据
     * @return true 解压成功，false 解压失败
     */
    static bool Decompress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
    
    /**
     * @brief 解压缩数据到字符串
     * @param input 待解压的数据
     * @param output 解压后的字符串
     * @return true 解压成功，false 解压失败
     */
    static bool Decompress(const std::vector<uint8_t>& input, std::string& output);
    
    /**
     * @brief 获取压缩率
     * @param originalSize 原始数据大小
     * @param compressedSize 压缩后数据大小
     * @return 压缩率百分比 (0.0-100.0)
     */
    static double GetCompressionRatio(size_t originalSize, size_t compressedSize);

private:
    // 禁止实例化
    GzipUtils() = delete;
    ~GzipUtils() = delete;
    GzipUtils(const GzipUtils&) = delete;
    GzipUtils& operator=(const GzipUtils&) = delete;
    
    // 内部压缩实现
    static bool CompressInternal(const uint8_t* input, size_t inputSize, 
                                std::vector<uint8_t>& output);
    
    // 内部解压实现
    static bool DecompressInternal(const uint8_t* input, size_t inputSize, 
                                  std::vector<uint8_t>& output);
};

} // namespace KMC

#endif // GZIP_UTILS_H