#ifndef READER_WRITER_LOCK_H
#define READER_WRITER_LOCK_H

#include <mutex>
#include <condition_variable>

namespace KMC {


/**
 * 读写锁类 - 实现写优先的读写锁机制
 * 允许多个读者同时访问，或一个写者独占访问
 */
class ReaderWriterLock {
public:
    ReaderWriterLock() : m_readers(0), m_writer(false), m_waiting_writers(0) {}

    ReaderWriterLock(const ReaderWriterLock&) = delete;
    ReaderWriterLock& operator=(const ReaderWriterLock&) = delete;
    ReaderWriterLock(ReaderWriterLock&&) = delete;
    ReaderWriterLock& operator=(ReaderWriterLock&&) = delete;

    /**
     * 获取读锁
     * 读者需要等待：
     * 1. 当有写者正在活跃时
     * 2. 当有写者正在等待时（写优先策略）
     */
    void lock_read() {
        std::unique_lock<std::mutex> lock(m_mutex);
        // 读者等待条件：有写者活跃 或 有写者在等待
        m_reader_cv.wait(lock, [this]() { return !m_writer && m_waiting_writers == 0; });
        m_readers++;
    }

    /**
     * 释放读锁
     * 如果当前是最后一个读者，且有写者在等待，则唤醒一个写者
     */
    void unlock_read() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_readers--;
        // 如果没有读者且有写者等待，唤醒一个写者
        if (m_readers == 0 && m_waiting_writers > 0) {
            m_writer_cv.notify_one();
        }
    }

    /**
     * 获取写锁
     * 写者需要等待：
     * 1. 当有读者正在活跃时
     * 2. 当有其他写者正在活跃时
     */
    void lock_write() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_waiting_writers++;  // 增加等待的写者计数
        // 写者等待条件：有读者活跃 或 有其他写者活跃
        m_writer_cv.wait(lock, [this]() { return m_readers == 0 && !m_writer; });
        m_waiting_writers--;  // 减少等待的写者计数
        m_writer = true;      // 标记写者活跃
    }

    /**
     * 释放写锁
     * 优先唤醒等待的写者，如果没有写者等待，则唤醒所有读者
     */
    void unlock_write() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_writer = false;  // 标记写者不再活跃
        // 优先唤醒等待的写者
        if (m_waiting_writers > 0) {
            m_writer_cv.notify_one();
        } else {
            // 没有写者等待时，唤醒所有等待的读者
            m_reader_cv.notify_all();
        }
    }

private:
    std::mutex m_mutex;                 // 互斥锁，保护内部状态
    std::condition_variable m_reader_cv;
    std::condition_variable m_writer_cv;
    int m_readers;          // 活跃读者的数量
    bool m_writer;          // 是否有写者活跃
    int m_waiting_writers;  // 等待的写者数量
};

/**
 * 读锁的RAII封装类
 * 构造时获取读锁，析构时自动释放读锁
 */
class ReadLockGuard {
public:
    explicit ReadLockGuard(ReaderWriterLock& rw_lock) : m_lock(rw_lock) {
        m_lock.lock_read();
    }
    ~ReadLockGuard() {
        m_lock.unlock_read();
    }

    ReadLockGuard(const ReadLockGuard&) = delete;
    ReadLockGuard& operator=(const ReadLockGuard&) = delete;
    ReadLockGuard(ReadLockGuard&&) = delete;
    ReadLockGuard& operator=(ReadLockGuard&&) = delete;

private:
    ReaderWriterLock& m_lock;  // 引用关联的读写锁
};

/**
 * 写锁的RAII封装类
 * 构造时获取写锁，析构时自动释放写锁
 */
class WriteLockGuard {
public:
    explicit WriteLockGuard(ReaderWriterLock& rw_lock) : m_lock(rw_lock) {
        m_lock.lock_write();
    }
    ~WriteLockGuard() {
        m_lock.unlock_write();
    }

    WriteLockGuard(const WriteLockGuard&) = delete;
    WriteLockGuard& operator=(const WriteLockGuard&) = delete;
    WriteLockGuard(WriteLockGuard&&) = delete;
    WriteLockGuard& operator=(WriteLockGuard&&) = delete;

private:
    ReaderWriterLock& m_lock;  // 引用关联的读写锁
};


} //KMC

#endif // READER_WRITER_LOCK_H