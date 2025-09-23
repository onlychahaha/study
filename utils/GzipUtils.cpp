#include "GzipUtils.h"
#include <cstring>

#include <zlib/zlib.h>

namespace KMC {

bool GzipUtils::Compress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }
    
    return CompressInternal(input.data(), input.size(), output);
}

bool GzipUtils::Compress(const std::string& input, std::vector<uint8_t>& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }
    
    return CompressInternal(reinterpret_cast<const uint8_t*>(input.c_str()), 
                           input.length(), output);
}

bool GzipUtils::Decompress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }
    
    return DecompressInternal(input.data(), input.size(), output);
}

bool GzipUtils::Decompress(const std::vector<uint8_t>& input, std::string& output) {
    std::vector<uint8_t> decompressed;
    if (!DecompressInternal(input.data(), input.size(), decompressed)) {
        return false;
    }
    
    if (decompressed.empty()) {
        output.clear();
        return true;
    }
    
    output.assign(reinterpret_cast<const char*>(decompressed.data()), 
                  decompressed.size());
    return true;
}

double GzipUtils::GetCompressionRatio(size_t originalSize, size_t compressedSize) {
    if (originalSize == 0) {
        return 0.0;
    }
    
    return (static_cast<double>(compressedSize) / originalSize) * 100.0;
}

bool GzipUtils::CompressInternal(const uint8_t* input, size_t inputSize, 
                                std::vector<uint8_t>& output) {
    // 估算压缩后的最大大小 (原始大小 + 12字节的gzip头部开销)
    uLong maxCompressedSize = compressBound(static_cast<uLong>(inputSize));
    if (maxCompressedSize == 0) {
        return false;
    }
    
    // 分配输出缓冲区
    output.resize(maxCompressedSize);
    
    // 初始化zlib流
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    
    // 使用gzip格式 (windowBits = 15 + 16)
    int ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                          15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        return false;
    }
    
    // 设置输入和输出
    stream.avail_in = static_cast<uInt>(inputSize);
    stream.next_in = const_cast<Bytef*>(input);
    stream.avail_out = static_cast<uInt>(output.size());
    stream.next_out = output.data();
    
    // 执行压缩
    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        return false;
    }
    
    // 调整输出大小
    output.resize(stream.total_out);
    
    // 清理资源
    deflateEnd(&stream);
    
    return true;
}

bool GzipUtils::DecompressInternal(const uint8_t* input, size_t inputSize, 
                                  std::vector<uint8_t>& output) {
    // 初始化zlib流
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    
    // 使用gzip格式解压 (windowBits = 15 + 16)
    int ret = inflateInit2(&stream, 15 + 16);
    if (ret != Z_OK) {
        return false;
    }
    
    // 设置输入
    stream.avail_in = static_cast<uInt>(inputSize);
    stream.next_in = const_cast<Bytef*>(input);
    
    // 动态分配输出缓冲区
    const size_t chunkSize = 4096; // 4KB块大小
    output.clear();
    output.reserve(inputSize * 2); // 预估解压后大小
    
    std::vector<uint8_t> chunk(chunkSize);
    
    do {
        stream.avail_out = static_cast<uInt>(chunk.size());
        stream.next_out = chunk.data();
        
        ret = inflate(&stream, Z_NO_FLUSH);
        
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || 
            ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&stream);
            return false;
        }
        
        // 计算本次解压的数据量
        size_t decompressedChunkSize = chunk.size() - stream.avail_out;
        
        // 将解压的数据添加到输出
        output.insert(output.end(), chunk.begin(), 
                     chunk.begin() + decompressedChunkSize);
        
    } while (ret != Z_STREAM_END);
    
    // 清理资源
    inflateEnd(&stream);
    
    return ret == Z_STREAM_END;
}

} // namespace KMC