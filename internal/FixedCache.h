#ifndef FIXED_CACHE_H
#define FIXED_CACHE_H

#include <unordered_map>
#include <string>
#include <memory>
#include <stdint.h>
#include <stdio.h>
#include "InternalStruct.h"
#include "ReaderWriterLock.h"

namespace KMC {

class FixedCache : public std::enable_shared_from_this<FixedCache>
{
public:
    typedef std::shared_ptr<FixedCache> ptr;
    FixedCache(size_t capacity = CACHEMAP_SIZE) : m_capacity(capacity) {}
    ~FixedCache();

    // 写操作需要互斥
    bool put(const std::string& key, std::shared_ptr<SessionContext> value);

    std::shared_ptr<SessionContext> get(const std::string& key) const;

    // 删除操作需要互斥
    std::shared_ptr<SessionContext> del(const std::string& key);

    // 查询已有元素个数
    size_t size() const;
    void clear();

private:
    std::unordered_map<std::string, std::shared_ptr<SessionContext>> m_cacheMap;
    mutable ReaderWriterLock m_cacheMutex;
    size_t m_capacity = CACHEMAP_SIZE;
};


} //KMC

#endif // FIXED_CACHE_H