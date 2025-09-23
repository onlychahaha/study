#ifndef SQLITE_CONNECTION_POOL_H_
#define SQLITE_CONNECTION_POOL_H_

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <sstream>

#include <sqlite/sqlite3.h>

namespace KMC {

// 数据库连接句柄类 - 负责单个连接的生命周期管理
class SqliteConnection {
public:
    explicit SqliteConnection(const std::string& db_path);
    ~SqliteConnection();

    SqliteConnection(const SqliteConnection&) = delete;
    SqliteConnection& operator=(const SqliteConnection&) = delete;

    SqliteConnection(SqliteConnection&& other) noexcept;
    SqliteConnection& operator=(SqliteConnection&& other) noexcept;

    // 获取原生句柄
    sqlite3* GetHandle() const { return m_db; }
    bool IsValid() const { return m_db != nullptr; }
    const std::string& GetPath() const { return m_dbPath; }

    // 基础数据库操作
    bool Open();
    void Close();
    std::string GetLastError() const;

private:
    bool CreateDirectoryIfNeeded();
    bool SetDatabasePragmas();

    std::string m_dbPath;
    sqlite3* m_db;
};

// 连接池配置
struct ConnectionPoolConfig {
    size_t initial_size = 2;        // 初始连接数
    size_t max_size = 10;           // 最大连接数
    size_t min_size = 1;            // 最小连接数
    std::chrono::seconds idle_timeout{300}; // 空闲连接超时时间(5分钟)
    std::chrono::seconds acquire_timeout{30}; // 获取连接超时时间(30秒)
};

// 连接包装器，用于自动归还连接
class PooledConnection {
public:
    PooledConnection(std::unique_ptr<SqliteConnection> conn, 
                    std::function<void(std::unique_ptr<SqliteConnection>)> returner);
    ~PooledConnection();
    
    // 禁用拷贝，允许移动
    PooledConnection(const PooledConnection&) = delete;
    PooledConnection& operator=(const PooledConnection&) = delete;
    PooledConnection(PooledConnection&& other) noexcept;
    PooledConnection& operator=(PooledConnection&& other) noexcept;
    
    // 获取原始连接
    SqliteConnection* operator->() const;
    SqliteConnection& operator*() const;
    SqliteConnection* get() const;
    sqlite3* GetHandle() const { return  m_connection->GetHandle();}
    bool IsValid() const { return m_connection->IsValid(); }
    
    // 手动归还连接
    void Release();
    
private:
    std::unique_ptr<SqliteConnection> m_connection;
    std::function<void(std::unique_ptr<SqliteConnection>)> m_returner;
    bool m_released;
};

// 连接池实现
class SqliteConnectionPool {
public:
    static SqliteConnectionPool& GetInstance();
    
    ~SqliteConnectionPool();
    
    // 初始化连接池
    bool Initialize(const std::string& db_path, const ConnectionPoolConfig& config = ConnectionPoolConfig{});
    
    // 获取连接（阻塞式）
    std::unique_ptr<PooledConnection> AcquireConnection();
    
    // 尝试获取连接（非阻塞）
    std::unique_ptr<PooledConnection> TryAcquireConnection();
    
    // 获取连接（带超时）
    std::unique_ptr<PooledConnection> AcquireConnection(const std::chrono::milliseconds& timeout);
    
    // 关闭连接池
    void Shutdown();
    
    // 获取连接池状态
    struct PoolStatus {
        size_t total_connections;
        size_t available_connections;
        size_t active_connections;
        bool is_initialized;
    };
    PoolStatus GetStatus() const;
    
private:
    SqliteConnectionPool() = default;
    
    // 创建新连接
    std::unique_ptr<SqliteConnection> CreateConnection();
    
    // 归还连接
    void ReturnConnection(std::unique_ptr<SqliteConnection> conn);
    
    // 清理空闲连接（后台任务）
    void CleanupIdleConnections();
    
    // 启动清理线程
    void StartCleanupThread();
    
    // 停止清理线程
    void StopCleanupThread();
    
    ConnectionPoolConfig m_config;
    std::string m_dbPath;
    
    mutable std::mutex m_mutex;
    std::condition_variable m_condition;
    
    std::queue<std::unique_ptr<SqliteConnection>> m_availableConnections;
    std::atomic<size_t> m_totalConnections{0};
    std::atomic<size_t> m_activeConnections{0};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdown{false};
    
    // 清理线程
    std::thread m_cleanupThread;
    std::atomic<bool> m_cleanupThreadRunning{false};

    //用于立即唤醒清理线程的同步原语
    std::condition_variable m_cleanupCondVar;
    std::mutex m_cleanupMutex;
};

} // namespace KMC

#endif // SQLITE_CONNECTION_POOL_H_