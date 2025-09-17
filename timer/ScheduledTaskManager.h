#ifndef SCHEDULED_TASK_MANAGER_H
#define SCHEDULED_TASK_MANAGER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include "KmcLogInterface.h"

namespace KMC {

// 定时任务状态
enum class SchedulerStatus {
    STOPPED,
    RUNNING,
    PAUSED,
    PENDING_UPDATE      // 等待更新下次执行时间
};

// 用户定时任务信息
struct UserScheduleInfo {
    std::string m_userUri;
    std::chrono::seconds m_interval;
    std::function<void(const std::string&)> m_taskFunc;
    SchedulerStatus m_status;
    std::chrono::steady_clock::time_point m_nextExecution;
    bool m_isDynamicSchedule; // true:为动态调度（根据到期时间计算） false:周期任务
};

class KeyMaterialScheduler {
public:
    typedef std::shared_ptr<KeyMaterialScheduler> ptr;
    
    KeyMaterialScheduler();
    ~KeyMaterialScheduler();
    
    // 禁止拷贝和赋值
    KeyMaterialScheduler(const KeyMaterialScheduler&) = delete;
    KeyMaterialScheduler& operator=(const KeyMaterialScheduler&) = delete;
    
    // 启动调度器
    void Start();
    
    // 停止调度器
    void Stop();
    
    // 添加用户定时任务
	bool AddUserTask(const std::string					   &userUri,
					 std::chrono::seconds					  interval,
					 std::function<void(const std::string &)> taskFunc,
					 bool isDynamicSchedule);

	// 移除用户定时任务
    bool RemoveUserTask(const std::string& userUri);
    
    // 更新用户任务间隔（热更新）
    bool UpdateUserInterval(const std::string& userUri, std::chrono::seconds newInterval);
    
    // 暂停用户任务
    bool PauseUserTask(const std::string& userUri);
    
    // 恢复用户任务
    bool ResumeUserTask(const std::string& userUri);
    
    // 检查用户任务是否存在
    bool HasUserTask(const std::string& userUri) const;
    
    // 获取用户任务状态
    SchedulerStatus GetUserTaskStatus(const std::string& userUri) const;
    
private:
    void SchedulerLoop();
    void ExecuteUserTask(const std::string& userUri);
    
    std::map<std::string, UserScheduleInfo> m_userTasks;
    mutable std::mutex m_tasksMutex;
    std::thread m_schedulerThread;
    std::atomic<bool> m_isRunning;
    std::condition_variable m_cv;
    std::mutex m_cvMutex;
    std::atomic<bool> m_shouldWakeup; //用于强制唤醒的标志
};

} //KMC

#endif // SCHEDULED_TASK_MANAGER_H