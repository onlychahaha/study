#include "IKmcService.h"
#include "KmcSvc.h"
#include <mutex>

namespace KMC {

std::unique_ptr<IKmcService> IKmcService::s_instance = nullptr;
std::mutex IKmcService::s_instanceMutex;

IKmcService& IKmcService::GetInstance() {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (!s_instance) {
        // 使用make_unique创建KmcSvc实例
        s_instance = std::unique_ptr<IKmcService>(new KmcSvc());
    }
    return *s_instance;
}

void IKmcService::DestroyInstance() {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (s_instance) {
        // 确保在销毁前进行清理
        s_instance->FinalizeKmc();
        s_instance.reset();
    }
}

} // namespace KMC