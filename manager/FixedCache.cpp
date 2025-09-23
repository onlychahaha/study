#include "FixedCache.h"
#include <iostream>

namespace KMC {

FixedCache::~FixedCache() {}

bool FixedCache::put(const std::string& key, std::shared_ptr<SessionContext> value) {
    WriteLockGuard lock(m_cacheMutex);

    if (m_cacheMap.size() >= m_capacity && m_cacheMap.find(key) == m_cacheMap.end()) { // 当更新现有key时，不检查容量
        // 缓存已满，无法插入新元素 (除非是更新现有元素)
        return false;
    }
    m_cacheMap[key] = value;

    return true;
}

std::shared_ptr<SessionContext> FixedCache::get(const std::string& key) const {
    ReadLockGuard lock(m_cacheMutex);
    auto it = m_cacheMap.find(key);
    if (it == m_cacheMap.end()) {
        return nullptr;
    }

    return it->second;
}

std::shared_ptr<SessionContext> FixedCache::del(const std::string& key) {
    WriteLockGuard lock(m_cacheMutex);

    auto it = m_cacheMap.find(key);
    if (it == m_cacheMap.end()) {
        return nullptr;
    }
    auto value = it->second;
    m_cacheMap.erase(it);
    return value;
}

void FixedCache::clear() {
    WriteLockGuard lock(m_cacheMutex);
    m_cacheMap.clear();
}

size_t FixedCache::size() const {
    ReadLockGuard lock(m_cacheMutex);
    return m_cacheMap.size();
}


} //KMC
