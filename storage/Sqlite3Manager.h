#ifndef SQLITE3MANAGER_H_
#define SQLITE3MANAGER_H_

#include <string>
#include <vector>
#include <memory>

#include <sqlite/sqlite3.h>
#include "SqliteConnectionPool.h"
#include "Commstruct.h"

namespace KMC {

// 数据库操作执行类 - 负责具体的数据库操作逻辑
class SqliteDatabase {
public:
    explicit SqliteDatabase();
    ~SqliteDatabase();

    // 禁用拷贝构造和赋值
    SqliteDatabase(const SqliteDatabase&) = delete;
    SqliteDatabase& operator=(const SqliteDatabase&) = delete;

    // 数据库操作接口
    bool InitializeTables();
    
    // 查询操作辅助方法
    bool PrepareStatement(const std::string& sql, sqlite3_stmt** stmt, PooledConnection& conn);
    bool BindStringParam(sqlite3_stmt* stmt, int index, const std::string& value);
    bool BindIntParam(sqlite3_stmt* stmt, int index, int value);
    bool BindInt64Param(sqlite3_stmt* stmt, int index, int64_t value);
    std::string GetStringColumn(sqlite3_stmt* stmt, int column);
    int GetIntColumn(sqlite3_stmt* stmt, int column);
    int64_t GetInt64Column(sqlite3_stmt* stmt, int column);
    void FinalizeStatement(sqlite3_stmt* stmt);
    // 获取最后插入的行ID和变更数量
    int64_t GetLastInsertRowId();
    int GetChanges();
    
    // 检查数据库是否可用
    bool IsAvailable() const;

    // 证书表操作
    bool InsertCertInfo(const CertInfos2& cert_info, OnlineMode mode);
    bool QueryOfflineCertInfo(CertInfos2& cert_info);
    bool DeleteCertInfo(const std::string& cert_uri);

    // 密钥材料表操作
    bool InsertKeyInfo(const KeyInfos2& key_info, OnlineMode mode, const std::string& encrypted_data);
    bool QueryKeyInfo(const std::string& user_uri, uint64_t key_period_no, KeyInfos2& key_info, std::string& encrypted_data);
    bool DeleteKeyInfo(const std::string& user_uri, uint64_t key_period_no);

    // GMK表操作
    bool InsertGmkInfo(const GmkInfo& gmk_info, const std::string& encrypted_data);
    bool QueryGmkInfo(const std::string& user_uri, const std::string& group_id, std::vector<GmkInfo>& gmk_infos);
    bool QueryGmkInfoByUser(const std::string& user_uri, std::vector<GmkInfo>& gmk_infos);
    bool DeleteGmkInfoByUserGroup(const std::string& user_uri, const std::string& group_id);
    
    // Raw GMK表操作
    bool InsertRawGmkInfo(const RawGmkInfo& raw_gmk_info);
    bool QueryRawGmkInfo(const std::string& user_uri, const std::string& group_id, RawGmkInfo& raw_gmk_info);
    bool QueryRawGmkInfo(const std::string& user_uri, const std::string& group_id, const std::string e_tag, RawGmkInfo& raw_gmk_info);
    bool UpdateRawGmkInfo(const std::string& user_uri, const std::string& group_id, const std::string e_tag, const RawGmkInfo& raw_gmk_info);
    bool DeleteRawGmkInfo(const std::string& user_uri, const std::string& group_id);
    bool DeleteRawGmkInfo(const std::string& user_uri, const std::string& group_id, std::string e_tag);

    // 清空数据表操作
    bool ClearAllTables();
    bool ClearCertTable();
    bool ClearKeyTable();
    bool ClearGmkTable();
    bool ClearRawGmkTable();

private:
    // 获取连接池中的连接
    std::unique_ptr<PooledConnection> GetConnection();
};

// RAII事务管理类
class SqliteTransaction {
public:
    explicit SqliteTransaction(PooledConnection& conn);
    ~SqliteTransaction();
    
    bool Begin();
    bool Commit();
    bool Rollback();
    
private:
    PooledConnection& m_conn;
    bool m_active;
    bool m_committed;
};

} // namespace KMC

#endif // SQLITE3MANAGER_H_