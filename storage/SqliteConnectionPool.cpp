#include "SqliteConnectionPool.h"

#include <unistd.h>
#include <sys/stat.h>

#include "utils/common-utils.h"

namespace KMC {

// SqliteConnection 实现
SqliteConnection::SqliteConnection(const std::string& db_path) 
    : m_dbPath(db_path), m_db(nullptr) {
}

SqliteConnection::~SqliteConnection() {
    Close();
}

SqliteConnection::SqliteConnection(SqliteConnection&& other) noexcept 
    : m_dbPath(std::move(other.m_dbPath)), m_db(other.m_db) {
    other.m_db = nullptr;
}

SqliteConnection& SqliteConnection::operator=(SqliteConnection&& other) noexcept {
    if (this != &other) {
        Close();
        m_dbPath = std::move(other.m_dbPath);
        m_db = other.m_db;
        other.m_db = nullptr;
    }
    return *this;
}

bool SqliteConnection::Open() {
    if (m_db) {
        return true; // 已经打开
    }

    // 创建目录
    if (!CreateDirectoryIfNeeded()) {
        kmclog_e(LOG_TAG, "Failed to create database directory for: %s", m_dbPath.c_str());
        return false;
    }

    // 打开数据库连接
    int result = sqlite3_open_v2(m_dbPath.c_str(), &m_db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                                nullptr);
    // int result = sqlite3_open(m_dbPath.c_str(), &m_db);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to open database %s: %s", 
                m_dbPath.c_str(), sqlite3_errmsg(m_db));
        if (m_db) {
            sqlite3_close(m_db);
            m_db = nullptr;
        }
        return false;
    }

    //设置数据库参数
    if (!SetDatabasePragmas()) {
        kmclog_w(LOG_TAG, "Failed to set database pragmas");
    }

    std::ostringstream oss;
    oss << std::this_thread::get_id();
    kmclog_i(LOG_TAG, "Database connection opened successfully: %s (thread: %S)", 
            m_dbPath.c_str(), oss.str().c_str());
    return true;
}

void SqliteConnection::Close() {
    if (m_db) {
        int result = sqlite3_close(m_db);
        if (result != SQLITE_OK) {
            kmclog_w(LOG_TAG, "Error closing database: %s", sqlite3_errmsg(m_db));
        } else {
            kmclog_i(LOG_TAG, "Database connection closed: %s", m_dbPath.c_str());
        }
        m_db = nullptr;
    }
}

std::string SqliteConnection::GetLastError() const {
    if (!m_db) {
        return "Database not opened";
    }
    return std::string(sqlite3_errmsg(m_db));
}

bool SqliteConnection::CreateDirectoryIfNeeded() {
    size_t lastSlash = m_dbPath.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return true; // 相对路径，无需创建目录
    }

    std::string dirPath = m_dbPath.substr(0, lastSlash);
    
    // 检查目录是否存在
    if (access(dirPath.c_str(), F_OK) == 0) {
        return true;
    }

    // 递归创建目录
    size_t pos = 1;
    while ((pos = dirPath.find('/', pos)) != std::string::npos) {
        std::string subDir = dirPath.substr(0, pos);
        if (access(subDir.c_str(), F_OK) != 0) {
            if (mkdir(subDir.c_str(), 0755) != 0) {
                kmclog_e(LOG_TAG, "Failed to create directory %s: %s", 
                        subDir.c_str(), strerror(errno));
                return false;
            }
        }
        pos++;
    }

    // 创建最终目录
    if (mkdir(dirPath.c_str(), 0755) != 0) {
        kmclog_e(LOG_TAG, "Failed to create directory %s: %s", 
                dirPath.c_str(), strerror(errno));
        return false;
    }

    return true;
}

bool SqliteConnection::SetDatabasePragmas() {
    if (!m_db) {
        return false;
    }

    // 启用外键约束
    char* error_msg = nullptr;
    int result = -1;
    //  result = qlite3_exec(m_db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, &error_msg);
    // if (result != SQLITE_OK) {
    //     kmclog_w(LOG_TAG, "Failed to enable foreign keys: %s", 
    //             error_msg ? error_msg : "Unknown error");
    //     if (error_msg) {
    //         sqlite3_free(error_msg);
    //     }
    //     return false;
    // }

    // 设置其他的参数
    const char* pragmas[] = {
        "PRAGMA journal_mode = WAL;",           // 启用WAL模式，提高并发性能
        "PRAGMA synchronous = NORMAL;",         // 平衡性能和安全性
        "PRAGMA cache_size = -64000;",          // 设置缓存大小为64MB
        "PRAGMA temp_store = MEMORY;",          // 临时表存储在内存中
    };

    for (const char* pragma : pragmas) {
        result = sqlite3_exec(m_db, pragma, nullptr, nullptr, &error_msg);
        if (result != SQLITE_OK) {
            kmclog_w(LOG_TAG, "Failed to execute pragma %s: %s", 
                    pragma, error_msg ? error_msg : "Unknown error");
            if (error_msg) {
                sqlite3_free(error_msg);
            }
        }
    }

    return true;
}


// PooledConnection 实现
PooledConnection::PooledConnection(std::unique_ptr<SqliteConnection> conn, 
                                  std::function<void(std::unique_ptr<SqliteConnection>)> returner)
    : m_connection(std::move(conn)), m_returner(std::move(returner)), m_released(false) {
}

PooledConnection::~PooledConnection() {
    Release();
}

PooledConnection::PooledConnection(PooledConnection&& other) noexcept 
    : m_connection(std::move(other.m_connection)), 
      m_returner(std::move(other.m_returner)),
      m_released(other.m_released) {
    other.m_released = true;
}

PooledConnection& PooledConnection::operator=(PooledConnection&& other) noexcept {
    if (this != &other) {
        Release();
        m_connection = std::move(other.m_connection);
        m_returner = std::move(other.m_returner);
        m_released = other.m_released;
        other.m_released = true;
    }
    return *this;
}

SqliteConnection* PooledConnection::operator->() const {
    return m_connection.get();
}

SqliteConnection& PooledConnection::operator*() const {
    return *m_connection;
}

SqliteConnection* PooledConnection::get() const {
    return m_connection.get();
}

void PooledConnection::Release() {
    if (!m_released && m_connection && m_returner) {
        m_returner(std::move(m_connection));
        m_released = true;
    }
}

// SqliteConnectionPool 实现
SqliteConnectionPool& SqliteConnectionPool::GetInstance() {
    static SqliteConnectionPool instance;
    return instance;
}

SqliteConnectionPool::~SqliteConnectionPool() {
    Shutdown();
}

bool SqliteConnectionPool::Initialize(const std::string& db_path, const ConnectionPoolConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        kmclog_w(LOG_TAG, "Connection pool already initialized");
        return true;
    }
    
    m_config = config;
    m_dbPath = db_path;
    
    // 创建初始连接
    for (size_t i = 0; i < m_config.initial_size; ++i) {
        auto conn = CreateConnection();
        if (!conn) {
            kmclog_e(LOG_TAG, "Failed to create initial connection %zu", i);
            return false;
        }
        m_availableConnections.push(std::move(conn));
        ++m_totalConnections;
    }
    
    m_initialized = true;
    m_shutdown = false;
    
    // 启动检测线程
    StartCleanupThread();
    
    kmclog_i(LOG_TAG, "Connection pool initialized with %zu connections", m_config.initial_size);
    return true;
}

std::unique_ptr<PooledConnection> SqliteConnectionPool::AcquireConnection() {
    return AcquireConnection(m_config.acquire_timeout);
}

std::unique_ptr<PooledConnection> SqliteConnectionPool::TryAcquireConnection() {
    return AcquireConnection(std::chrono::milliseconds(0));
}

std::unique_ptr<PooledConnection> SqliteConnectionPool::AcquireConnection(const std::chrono::milliseconds& timeout) {
    std::unique_lock<std::mutex> lock(m_mutex);
    
    if (!m_initialized || m_shutdown) {
        kmclog_e(LOG_TAG, "Connection pool not initialized or shut down");
        return nullptr;
    }
    
    auto deadline = std::chrono::steady_clock::now() + timeout;
    
    while (m_availableConnections.empty() && m_totalConnections >= m_config.max_size) {
        if (timeout.count() == 0) {
            // 非阻塞模式
            return nullptr;
        }
        
        if (m_condition.wait_until(lock, deadline) == std::cv_status::timeout) {
            kmclog_w(LOG_TAG, "Timeout waiting for available connection");
            return nullptr;
        }
        
        if (m_shutdown) {
            return nullptr;
        }
    }
    
    std::unique_ptr<SqliteConnection> conn;
    
    if (!m_availableConnections.empty()) {
        // 使用现有连接
        conn = std::move(m_availableConnections.front());
        m_availableConnections.pop();
    } else if (m_totalConnections < m_config.max_size) {
        // 创建新连接
        lock.unlock();
        conn = CreateConnection();
        lock.lock();
        
        if (!conn) {
            kmclog_e(LOG_TAG, "Failed to create new connection");
            return nullptr;
        }
        ++m_totalConnections;
    }
    
    if (!conn) {
        return nullptr;
    }
    
    // 验证连接是否有效
    if (!conn->IsValid()) {
        if (!conn->Open()) {
            kmclog_e(LOG_TAG, "Failed to open database connection");
            --m_totalConnections;
            return nullptr;
        }
    }
    
    ++m_activeConnections;
    
    // 创建归还函数
    auto returner = [this](std::unique_ptr<SqliteConnection> returned_conn) {
        ReturnConnection(std::move(returned_conn));
    };
    
    return std::unique_ptr<PooledConnection>(new PooledConnection(std::move(conn), returner));
}

void SqliteConnectionPool::ReturnConnection(std::unique_ptr<SqliteConnection> conn) {
    if (!conn) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_shutdown) {
        --m_totalConnections;
        --m_activeConnections;
        return;
    }
    
    // 检查连接是否仍然有效
    if (conn->IsValid()) {
        m_availableConnections.push(std::move(conn));
    } else {
        kmclog_w(LOG_TAG, "Returned connection is invalid, discarding");
        --m_totalConnections;
    }
    
    --m_activeConnections;
    m_condition.notify_one();
}

void SqliteConnectionPool::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized || m_shutdown) {
            return;
        }
        m_shutdown = true;
    }
    
    m_condition.notify_all();
    
    // 停止清理线程
    StopCleanupThread();
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // 清空可用连接
        while (!m_availableConnections.empty()) {
            m_availableConnections.pop();
            --m_totalConnections;
        }
        
        m_initialized = false;
    }
    
    kmclog_i(LOG_TAG, "Connection pool shut down");
}

SqliteConnectionPool::PoolStatus SqliteConnectionPool::GetStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    PoolStatus status;
    status.total_connections = m_totalConnections;
    status.available_connections = m_availableConnections.size();
    status.active_connections = m_activeConnections;
    status.is_initialized = m_initialized;
    
    return status;
}

std::unique_ptr<SqliteConnection> SqliteConnectionPool::CreateConnection() {
    auto conn = std::unique_ptr<SqliteConnection>(new SqliteConnection(m_dbPath));
    if (!conn->Open()) {
        kmclog_e(LOG_TAG, "Failed to open new database connection");
        return nullptr;
    }
    return conn;
}

void SqliteConnectionPool::StartCleanupThread()
{
	if (m_cleanupThreadRunning) {
		return;
	}

	m_cleanupThreadRunning = true;
	m_cleanupThread = std::thread([this]() {
		std::unique_lock<std::mutex> lock(m_cleanupMutex);
		while (m_cleanupThreadRunning && !m_shutdown) {
			// 等待1分钟或被停止信号唤醒
			if (m_cleanupCondVar.wait_for(lock, std::chrono::minutes(1), [this] {
					return !m_cleanupThreadRunning || m_shutdown;
				})) {
				// 条件满足（停止信号被触发）
				break;
			}

			// 超时（1分钟到了）
			if (m_cleanupThreadRunning && !m_shutdown) {
				CleanupIdleConnections();
			}
		}
	});
}

void SqliteConnectionPool::StopCleanupThread()
{
	{
		std::lock_guard<std::mutex> lock(m_cleanupMutex);
		m_cleanupThreadRunning = false;
	}
	m_cleanupCondVar.notify_all(); // 立即唤醒等待的线程

	if (m_cleanupThread.joinable()) {
		m_cleanupThread.join();
	}
}

void SqliteConnectionPool::CleanupIdleConnections() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // 如果连接数超过最小值，可以清理一些空闲连接
    while (m_availableConnections.size() > m_config.min_size && 
           m_totalConnections > m_config.min_size) {
        m_availableConnections.pop();
        --m_totalConnections;
    }
}

} // namespace KMC