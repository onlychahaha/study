#include "ScheduledTaskManager.h"
#include "Commstruct.h"

namespace KMC {


KeyMaterialScheduler::KeyMaterialScheduler() 
    : m_isRunning(false), m_shouldWakeup(false) {
}

KeyMaterialScheduler::~KeyMaterialScheduler() {
    Stop();
}

void KeyMaterialScheduler::Start() {
    if (m_isRunning) {
        kmclog_w(LOG_TAG, "KeyMaterialScheduler already running");
        return;
    }
    
    m_isRunning = true;
    m_schedulerThread = std::thread(&KeyMaterialScheduler::SchedulerLoop, this);
    
    kmclog_i(LOG_TAG, "KeyMaterialScheduler started");
}

void KeyMaterialScheduler::Stop() {
    if (!m_isRunning.load()) {
        return;
    }
    
    m_isRunning.store(false);
    m_shouldWakeup.store(true); 
    m_cv.notify_all();
    
    if (m_schedulerThread.joinable()) {
        m_schedulerThread.join();
    }
    
    kmclog_i(LOG_TAG, "KeyMaterialScheduler stopped");
}

bool KeyMaterialScheduler::AddUserTask(const std::string& userUri, 
                                       std::chrono::seconds interval,
                                       std::function<void(const std::string&)> taskFunc,
                                       bool isDynamicSchedule) {
    if (userUri.empty() || interval.count() <= 0 || !taskFunc) {
        kmclog_e(LOG_TAG, "Invalid parameters for AddUserTask");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    if (m_userTasks.find(userUri) != m_userTasks.end()) {
        kmclog_w(LOG_TAG, "User task %s already exists, updating...", userUri.c_str());
        // 更新现有任务
        m_userTasks[userUri].m_interval = interval;
        m_userTasks[userUri].m_taskFunc = taskFunc;
        m_userTasks[userUri].m_isDynamicSchedule = isDynamicSchedule;
        m_userTasks[userUri].m_nextExecution = std::chrono::steady_clock::now() + interval;
    } else {
        // 创建新任务
        UserScheduleInfo userInfo;
        userInfo.m_userUri = userUri;
        userInfo.m_interval = interval;
        userInfo.m_taskFunc = taskFunc;
        userInfo.m_status = SchedulerStatus::RUNNING;
        userInfo.m_isDynamicSchedule = isDynamicSchedule;
        
        // 否则按正常间隔执行
        userInfo.m_nextExecution = std::chrono::steady_clock::now() + interval;
        
        m_userTasks[userUri] = userInfo;
    }
    
    kmclog_i(LOG_TAG, "User task %s added/updated with interval %ld seconds, dynamic=%s", 
             userUri.c_str(), interval.count(), isDynamicSchedule ? "true" : "false");
    
    // 如果调度器正在运行，唤醒调度线程
    if (m_isRunning) {
        m_shouldWakeup.store(true);
        m_cv.notify_one();
    }
    
    return true;
}

bool KeyMaterialScheduler::RemoveUserTask(const std::string& userUri) {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    auto it = m_userTasks.find(userUri);
    if (it == m_userTasks.end()) {
        kmclog_w(LOG_TAG, "User task %s not found", userUri.c_str());
        return false;
    }
    
    m_userTasks.erase(it);
    kmclog_i(LOG_TAG, "User task %s removed", userUri.c_str());
    
    return true;
}

bool KeyMaterialScheduler::UpdateUserInterval(const std::string& userUri, 
                                              std::chrono::seconds newInterval) {
    if (newInterval.count() <= 0) {
        kmclog_e(LOG_TAG, "Invalid interval for user %s", userUri.c_str());
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    auto it = m_userTasks.find(userUri);
    if (it == m_userTasks.end()) {
        kmclog_w(LOG_TAG, "User task %s not found", userUri.c_str());
        return false;
    }
    
    it->second.m_interval = newInterval;
    it->second.m_nextExecution = std::chrono::steady_clock::now() + newInterval;
    
    // 如果当前状态是PENDING_UPDATE，恢复为RUNNING
    if (it->second.m_status == SchedulerStatus::PENDING_UPDATE) {
        it->second.m_status = SchedulerStatus::RUNNING;
    }
    
    kmclog_i(LOG_TAG, "User task %s interval updated to %ld seconds", 
             userUri.c_str(), newInterval.count());
    
    // 唤醒调度线程
    m_shouldWakeup.store(true);
    m_cv.notify_one();
    
    return true;
}

bool KeyMaterialScheduler::PauseUserTask(const std::string& userUri) {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    auto it = m_userTasks.find(userUri);
    if (it == m_userTasks.end()) {
        kmclog_w(LOG_TAG, "User task %s not found", userUri.c_str());
        return false;
    }
    
    it->second.m_status = SchedulerStatus::PAUSED;
    kmclog_i(LOG_TAG, "User task %s paused", userUri.c_str());
    
    return true;
}

bool KeyMaterialScheduler::ResumeUserTask(const std::string& userUri) {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    auto it = m_userTasks.find(userUri);
    if (it == m_userTasks.end()) {
        kmclog_w(LOG_TAG, "User task %s not found", userUri.c_str());
        return false;
    }
    
    it->second.m_status = SchedulerStatus::RUNNING;
    // 重新计算下次执行时间
    it->second.m_nextExecution = std::chrono::steady_clock::now() + it->second.m_interval;
    
    kmclog_i(LOG_TAG, "User task %s resumed", userUri.c_str());
    
    // 唤醒调度线程
    m_shouldWakeup.store(true);
    m_cv.notify_one();
    
    return true;
}

bool KeyMaterialScheduler::HasUserTask(const std::string& userUri) const {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    return m_userTasks.find(userUri) != m_userTasks.end();
}

SchedulerStatus KeyMaterialScheduler::GetUserTaskStatus(const std::string& userUri) const {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    auto it = m_userTasks.find(userUri);
    if (it == m_userTasks.end()) {
        return SchedulerStatus::STOPPED;
    }
    
    return it->second.m_status;
}

void KeyMaterialScheduler::SchedulerLoop() {
    while (m_isRunning.load()) {
        auto now = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point nextWakeup = now + std::chrono::minutes(30);
        bool hasValidWakeupTime = false;
        
        {
            std::lock_guard<std::mutex> lock(m_tasksMutex);
            
            for (auto& pair : m_userTasks) {
                UserScheduleInfo& userInfo = pair.second;
                
                if (userInfo.m_status == SchedulerStatus::RUNNING && now >= userInfo.m_nextExecution) {
                    // 异步执行任务，避免阻塞调度循环
                    auto userUri = pair.first;
                    
                    if (userInfo.m_isDynamicSchedule) {
                        // 动态调度任务：标记为等待更新状态
                        userInfo.m_status = SchedulerStatus::PENDING_UPDATE;
                    } else {
                        // 固定周期任务：直接计算下次执行时间，状态保持RUNNING
                        userInfo.m_nextExecution = now + userInfo.m_interval;
                    }
                    
                    std::thread([this, userUri]() {
                        ExecuteUserTask(userUri);
                    }).detach();
                }
                
                // 找到最近的有效执行时间
                if (userInfo.m_status == SchedulerStatus::RUNNING && 
                    userInfo.m_nextExecution < nextWakeup) {
                    nextWakeup = userInfo.m_nextExecution;
                    hasValidWakeupTime = true;
                }
            }
        }
        
        // 等待到下次执行时间或被唤醒
        std::unique_lock<std::mutex> cvLock(m_cvMutex);
        m_cv.wait_until(cvLock, nextWakeup, [this] { 
            return m_shouldWakeup.load() || !m_isRunning.load(); 
        });
        
        m_shouldWakeup.store(false);
        
        if (!m_isRunning.load()) {
            break;
        }
    }
}

void KeyMaterialScheduler::ExecuteUserTask(const std::string& userUri) {
    UserScheduleInfo userInfo;
    {
        std::lock_guard<std::mutex> lock(m_tasksMutex);
        auto it = m_userTasks.find(userUri);
        if (it == m_userTasks.end()) {
            return;
        }
        // 仅复制任务函数，避免持有锁执行
        userInfo.m_taskFunc = it->second.m_taskFunc;
    }
    
    // 检查任务函数是否有效
    if (!userInfo.m_taskFunc) {
        kmclog_e(LOG_TAG, "Task function is null for user %s", userUri.c_str());
        return;
    }
    
    try {
        kmclog_i(LOG_TAG, "Executing scheduled key material download for user %s", userUri.c_str());
        userInfo.m_taskFunc(userUri);
        kmclog_i(LOG_TAG, "Scheduled key material download completed for user %s", userUri.c_str());
        
        
    } catch (...) {
		kmclog_e(LOG_TAG, "Scheduled key material download failed for user %s",
				 userUri.c_str());
		// 执行失败，恢复状态
		std::lock_guard<std::mutex> lock(m_tasksMutex);
		auto						it = m_userTasks.find(userUri);
		if (it != m_userTasks.end()) {
			it->second.m_status = SchedulerStatus::RUNNING;
			// 设置重试时间
			it->second.m_nextExecution =
					std::chrono::steady_clock::now() + std::chrono::minutes(10);
		}
	}
}


} //KMC