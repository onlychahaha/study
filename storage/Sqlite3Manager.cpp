#include "Sqlite3Manager.h"
#include <cstdlib>
#include <cstring>

#include "LocalDataEncryptUtils.h"
#include "KmcUtils.h"
#include "KmcLogInterface.h"

#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>

namespace KMC {


// SqliteDatabase 实现
SqliteDatabase::SqliteDatabase() {
    // 构造函数不需要数据库路径参数，因为连接池已经配置了路径
}

SqliteDatabase::~SqliteDatabase() {
    // 不需要清理，连接会自动归还到连接池
}

std::unique_ptr<PooledConnection> SqliteDatabase::GetConnection() {
    std::unique_ptr<KMC::PooledConnection> conn = SqliteConnectionPool::GetInstance().AcquireConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to acquire database connection from pool");
        return nullptr;
    }
    
    if (!conn->IsValid()) {
        kmclog_e(LOG_TAG, "Acquired invalid database connection");
        return nullptr;
    }
    
    return conn;
}

bool SqliteDatabase::IsAvailable() const {
    // 尝试获取连接来检查数据库是否可用
    auto conn = SqliteConnectionPool::GetInstance().TryAcquireConnection();
    return conn && conn->IsValid();
}

bool SqliteDatabase::InitializeTables() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for table initialization");
        return false;
    }

    // 创建群证书信息表
    const char* cert_table_sql = R"(
        CREATE TABLE IF NOT EXISTS cert_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_uri TEXT NOT NULL UNIQUE,
            kms_uri TEXT NOT NULL,
            version TEXT NOT NULL,
            pub_enc_key TEXT NOT NULL,
            pub_auth_key TEXT NOT NULL,
            user_key_period TEXT NOT NULL,
            user_key_offset TEXT NOT NULL,
            valid_from TEXT NOT NULL,
            valid_to TEXT,
            revoked INTEGER DEFAULT 0,
            online_mode INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cert_mode ON cert_table(online_mode);
    )";

    // 创建密钥信息表
    const char* key_table_sql = R"(
        CREATE TABLE IF NOT EXISTS key_material_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_uri TEXT NOT NULL,
            kms_uri TEXT NOT NULL,
            user_uri TEXT NOT NULL,
            user_id TEXT NOT NULL,
            key_period_no INTEGER NOT NULL,
            encrypted_material TEXT NOT NULL,
            valid_from TEXT NOT NULL,
            valid_to TEXT NOT NULL,
            online_mode INTEGER NOT NULL,
            UNIQUE(user_uri, key_period_no)
        );
        CREATE INDEX IF NOT EXISTS idx_key_user_uri ON key_material_table(user_uri);
        CREATE INDEX IF NOT EXISTS idx_key_mode ON key_material_table(online_mode);
    )";

    // 创建群组密钥表
    const char* gmk_table_sql = R"(
        CREATE TABLE IF NOT EXISTS gmk_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            e_tag TEXT NOT NULL,
            gmk_id TEXT NOT NULL,
            user_uri TEXT NOT NULL,
            group_id TEXT NOT NULL,
            guk_id TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            expire_time TEXT,
            activate_time TEXT,
            UNIQUE(user_uri, group_id, gmk_id)
        );
        CREATE INDEX IF NOT EXISTS idx_gmk_user_group ON gmk_table(user_uri, group_id);
        CREATE INDEX IF NOT EXISTS idx_gmk_gmk_id ON gmk_table(gmk_id);
    )";


    const char* raw_gmk_table_sql = R"(
        CREATE TABLE IF NOT EXISTS raw_gmk_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uri TEXT NOT NULL,
            group_id TEXT NOT NULL,
            gms_uri TEXT NOT NULL,
            e_tag TEXT NOT NULL,
            gmkMikey TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_raw_gmk_user_group ON raw_gmk_table(user_uri, group_id);
        CREATE INDEX IF NOT EXISTS idx_raw_gmk_etag ON raw_gmk_table(e_tag);
    )";

    SqliteTransaction transaction(*conn);
    if (!transaction.Begin()) {
        kmclog_e(LOG_TAG, "Failed to begin transaction for table creation");
        return false;
    }

    char* error_msg = nullptr;
    sqlite3* db = conn->GetHandle();

    // 创建证书表
    int result = sqlite3_exec(db, cert_table_sql, nullptr, nullptr, &error_msg);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to create cert_table table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) sqlite3_free(error_msg);
        return false;
    }

    // 创建密钥表
    result = sqlite3_exec(db, key_table_sql, nullptr, nullptr, &error_msg);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to create key_table table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) sqlite3_free(error_msg);
        return false;
    }

    // 创建群组密钥表
    result = sqlite3_exec(db, gmk_table_sql, nullptr, nullptr, &error_msg);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to create gmk_table table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) sqlite3_free(error_msg);
        return false;
    }

    result = sqlite3_exec(db, raw_gmk_table_sql, nullptr, nullptr, &error_msg);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to create raw_gmk_table table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) sqlite3_free(error_msg);
        return false;
    }

    if (!transaction.Commit()) {
        kmclog_e(LOG_TAG, "Failed to commit table creation transaction");
        return false;
    }

    kmclog_i(LOG_TAG, "Database tables initialized successfully");
    return true;
}

bool SqliteDatabase::PrepareStatement(const std::string& sql, sqlite3_stmt** stmt, PooledConnection& conn) {
    int result = sqlite3_prepare_v2(conn.GetHandle(), sql.c_str(), -1, stmt, nullptr);
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to prepare statement: %s, Error: %s", 
                sql.c_str(), sqlite3_errmsg(conn.GetHandle()));
        return false;
    }
    return true;
}

bool SqliteDatabase::BindStringParam(sqlite3_stmt* stmt, int index, const std::string& value) {
    if (!stmt) {
        return false;
    }

    int result = sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_STATIC);
    return result == SQLITE_OK;
}

bool SqliteDatabase::BindIntParam(sqlite3_stmt* stmt, int index, int value) {
    if (!stmt) {
        return false;
    }

    int result = sqlite3_bind_int(stmt, index, value);
    return result == SQLITE_OK;
}

bool SqliteDatabase::BindInt64Param(sqlite3_stmt* stmt, int index, int64_t value) {
    if (!stmt) {
        return false;
    }

    int result = sqlite3_bind_int64(stmt, index, value);
    return result == SQLITE_OK;
}

std::string SqliteDatabase::GetStringColumn(sqlite3_stmt* stmt, int column) {
    if (!stmt) {
        return "";
    }

    const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, column));
    return text ? std::string(text) : "";
}

int SqliteDatabase::GetIntColumn(sqlite3_stmt* stmt, int column) {
    if (!stmt) {
        return 0;
    }

    return sqlite3_column_int(stmt, column);
}

int64_t SqliteDatabase::GetInt64Column(sqlite3_stmt* stmt, int column) {
    if (!stmt) {
        return 0;
    }

    return sqlite3_column_int64(stmt, column);
}

void SqliteDatabase::FinalizeStatement(sqlite3_stmt* stmt) {
    if (stmt) {
        sqlite3_finalize(stmt);
    }
}

int64_t SqliteDatabase::GetLastInsertRowId() {
    auto conn = GetConnection();
    sqlite3* db = conn->GetHandle();
    
    if (!db) {
        return 0;
    }
    return sqlite3_last_insert_rowid(db);
}

int SqliteDatabase::GetChanges() {
    auto conn = GetConnection();
    sqlite3* db = conn->GetHandle();
    
    if (!db) {
        return 0;
    }
    return sqlite3_changes(db);
}

bool SqliteDatabase::InsertCertInfo(const CertInfos2& cert_info, OnlineMode mode) {
    auto conn = GetConnection();
    const std::string sql = R"(
        INSERT OR REPLACE INTO cert_table 
        (cert_uri, kms_uri, version, pub_enc_key, pub_auth_key, 
         user_key_period, user_key_offset, valid_from, valid_to, 
         revoked, online_mode) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    // 将uint64_t转换为字符串存储
    std::string user_key_period_str = KmcUtils::uint64ToString(cert_info.userKeyPeriod);
    std::string user_key_offset_str = KmcUtils::uint64ToString(cert_info.userKeyOffset);

    bool success = true;
    success &= BindStringParam(stmt, 1, cert_info.certUri);
    success &= BindStringParam(stmt, 2, cert_info.kmsUri);
    success &= BindStringParam(stmt, 3, cert_info.version);
    success &= BindStringParam(stmt, 4, cert_info.pubEncKey);
    success &= BindStringParam(stmt, 5, cert_info.pubAuthKey);
    success &= BindStringParam(stmt, 6, user_key_period_str);
    success &= BindStringParam(stmt, 7, user_key_offset_str);
    success &= BindStringParam(stmt, 8, cert_info.validFrom);
    success &= BindStringParam(stmt, 9, cert_info.validTo);
    success &= BindIntParam(stmt, 10, cert_info.revoked ? 1 : 0);
    success &= BindIntParam(stmt, 11, static_cast<int>(mode));

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to insert cert info: %s", sqlite3_errmsg(conn->GetHandle()));
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::QueryOfflineCertInfo(CertInfos2& cert_info) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get database connection for offline cert query");
        return false;
    }

    const std::string sql = R"(
        SELECT cert_uri, kms_uri, version, pub_enc_key, pub_auth_key, 
               user_key_period, user_key_offset, valid_from, valid_to, revoked
        FROM cert_table 
        WHERE online_mode = ? 
        ORDER BY valid_from DESC 
        LIMIT 1
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindIntParam(stmt, 1, static_cast<int>(OnlineMode::OFFLINE))) {
        FinalizeStatement(stmt);
        return false;
    }

    bool found = false;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        cert_info.certUri = GetStringColumn(stmt, 0);
        cert_info.kmsUri = GetStringColumn(stmt, 1);
        cert_info.version = GetStringColumn(stmt, 2);
        cert_info.pubEncKey = GetStringColumn(stmt, 3);
        cert_info.pubAuthKey = GetStringColumn(stmt, 4);
        
        // 将字符串转换为uint64_t
        std::string user_key_period_str = GetStringColumn(stmt, 5);
        std::string user_key_offset_str = GetStringColumn(stmt, 6);
        cert_info.userKeyPeriod = std::stoull(user_key_period_str);
        cert_info.userKeyOffset = std::stoull(user_key_offset_str);
        
        cert_info.validFrom = GetStringColumn(stmt, 7);
        cert_info.validTo = GetStringColumn(stmt, 8);
        cert_info.revoked = (GetIntColumn(stmt, 9) != 0);
        
        found = true;
        kmclog_i(LOG_TAG, "Successfully queried offline certificate: %s", cert_info.certUri.c_str());
    } else if (result == SQLITE_DONE) {
        kmclog_d(LOG_TAG, "No offline certificate found in database");
    } else {
        kmclog_e(LOG_TAG, "Error querying offline certificate: %s", sqlite3_errmsg(conn->GetHandle()));
    }

    FinalizeStatement(stmt);
    return found;
}

bool SqliteDatabase::DeleteCertInfo(const std::string& cert_uri) {
    auto conn = GetConnection();
    const std::string sql = R"(
        DELETE FROM cert_table WHERE cert_uri = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, cert_uri)) {
        FinalizeStatement(stmt);
        return false;
    }

    int result = sqlite3_step(stmt);
    bool success = (result == SQLITE_DONE);

    if (!success) {
        kmclog_e(LOG_TAG, "Failed to delete cert info: %s", sqlite3_errmsg(conn->GetHandle()));
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::InsertKeyInfo(const KeyInfos2& key_info, OnlineMode mode, const std::string& encrypted_data) {
    auto conn = GetConnection();
    const std::string sql = R"(
        INSERT OR REPLACE INTO key_material_table 
        (cert_uri, kms_uri, user_uri, user_id, key_period_no, 
         encrypted_material, valid_from, valid_to, online_mode) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, key_info.certUri);
    success &= BindStringParam(stmt, 2, key_info.kmsUri);
    success &= BindStringParam(stmt, 3, key_info.userUri);
    success &= BindStringParam(stmt, 4, key_info.userID);
    success &= BindInt64Param(stmt, 5, static_cast<int64_t>(key_info.keyPeriodNo));
    success &= BindStringParam(stmt, 6, encrypted_data);
    success &= BindStringParam(stmt, 7, key_info.validFrom);
    success &= BindStringParam(stmt, 8, key_info.validTo);
    success &= BindIntParam(stmt, 9, static_cast<int>(mode));

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to insert key material: %s", sqlite3_errmsg(conn->GetHandle()));
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::QueryKeyInfo(const std::string& user_uri, uint64_t key_period_no, KeyInfos2& key_info, std::string& encrypted_data) {
    auto conn = GetConnection();
    const std::string sql = R"(
        SELECT cert_uri, kms_uri, user_uri, user_id, key_period_no, 
               encrypted_material, valid_from, valid_to
        FROM key_material_table WHERE user_uri = ? AND key_period_no = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, user_uri) || !BindInt64Param(stmt, 2, static_cast<int64_t>(key_period_no))) {
        FinalizeStatement(stmt);
        return false;
    }

    bool found = false;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        key_info.certUri = GetStringColumn(stmt, 0);
        key_info.kmsUri = GetStringColumn(stmt, 1);
        key_info.userUri = GetStringColumn(stmt, 2);
        key_info.userID = GetStringColumn(stmt, 3);
        key_info.keyPeriodNo = static_cast<uint64_t>(GetInt64Column(stmt, 4));
        encrypted_data = GetStringColumn(stmt, 5);
        key_info.validFrom = GetStringColumn(stmt, 6);
        key_info.validTo = GetStringColumn(stmt, 7);

        found = true;
    }

    FinalizeStatement(stmt);
    return found;
}

bool SqliteDatabase::DeleteKeyInfo(const std::string& user_uri, uint64_t key_period_no) {
    auto conn = GetConnection();
    const std::string sql = R"(
        DELETE FROM key_material_table WHERE user_uri = ? AND key_period_no = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, user_uri);
    success &= BindInt64Param(stmt, 2, static_cast<int64_t>(key_period_no));

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to delete key info: %s", sqlite3_errmsg(conn->GetHandle()));
        }
    }

    FinalizeStatement(stmt);
    return success;
}

// GMK表操作实现
bool SqliteDatabase::InsertGmkInfo(const GmkInfo& gmk_info, const std::string& encrypted_data) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for inserting gmk info");
        return false;
    }

    // 首先检查该用户的GMK数量
    const std::string count_sql = "SELECT COUNT(*) FROM gmk_table WHERE user_uri = ?";
    sqlite3_stmt* count_stmt = nullptr;
    if (!PrepareStatement(count_sql, &count_stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(count_stmt, 1, gmk_info.userUri)) {
        FinalizeStatement(count_stmt);
        return false;
    }

    int count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        count = GetIntColumn(count_stmt, 0);
    }
    FinalizeStatement(count_stmt);

    // 如果数量达到限制，删除最旧的记录
    const int MAX_GMK_ENTRIES_PER_USER = 2000;
    if (count >= MAX_GMK_ENTRIES_PER_USER) {
        const std::string delete_sql = R"(
            DELETE FROM gmk_table WHERE id IN (
                SELECT id FROM gmk_table WHERE user_uri = ? 
                ORDER BY id ASC LIMIT ?
            )
        )";
        
        sqlite3_stmt* delete_stmt = nullptr;
        if (PrepareStatement(delete_sql, &delete_stmt, *conn)) {
            BindStringParam(delete_stmt, 1, gmk_info.userUri);
            BindIntParam(delete_stmt, 2, count - MAX_GMK_ENTRIES_PER_USER + 1);
            
            int result = sqlite3_step(delete_stmt);
            if (result == SQLITE_DONE) {
                kmclog_i(LOG_TAG, "Cleaned up old GMK entries for user: %s", gmk_info.userUri.c_str());
            } else {
                kmclog_w(LOG_TAG, "Failed to cleanup old GMK entries: %s", sqlite3_errmsg(conn->GetHandle()));
            }
            FinalizeStatement(delete_stmt);
        }
    }

    // 插入新记录
    const std::string sql = R"(
        INSERT OR REPLACE INTO gmk_table 
        (e_tag, gmk_id, user_uri, group_id, guk_id, encrypted_data, expire_time, activate_time) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, gmk_info.eTag);
    success &= BindStringParam(stmt, 2, gmk_info.gmkId);
    success &= BindStringParam(stmt, 3, gmk_info.userUri);
    success &= BindStringParam(stmt, 4, gmk_info.groupId);
    success &= BindStringParam(stmt, 5, gmk_info.gukId);
    success &= BindStringParam(stmt, 6, encrypted_data);
    success &= BindStringParam(stmt, 7, gmk_info.expireTime);
    success &= BindStringParam(stmt, 8, gmk_info.activateTime);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to insert gmk info: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "GMK info inserted successfully for user: %s, group: %s", 
                    gmk_info.userUri.c_str(), gmk_info.groupId.c_str());
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::QueryGmkInfo(const std::string& user_uri, const std::string& group_id, 
                                  std::vector<GmkInfo>& gmk_infos) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for querying gmk info");
        return false;
    }

    const std::string sql = R"(
        SELECT id, e_tag, gmk_id, user_uri, group_id, guk_id, encrypted_data, expire_time, activate_time
        FROM gmk_table WHERE user_uri = ? AND group_id = ?
        ORDER BY id
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, user_uri) || !BindStringParam(stmt, 2, group_id)) {
        FinalizeStatement(stmt);
        return false;
    }

    gmk_infos.clear(); // 清空输出vector
    
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        GmkInfo gmk_info;
        gmk_info.id = static_cast<uint64_t>(GetInt64Column(stmt, 0));
        gmk_info.eTag = GetStringColumn(stmt, 1);
        gmk_info.gmkId = GetStringColumn(stmt, 2);
        gmk_info.userUri = GetStringColumn(stmt, 3);
        gmk_info.groupId = GetStringColumn(stmt, 4);
        gmk_info.gukId = GetStringColumn(stmt, 5);
        
        // 获取加密数据并解密
        std::string encrypted_data = GetStringColumn(stmt, 6);
        if (!encrypted_data.empty()) {
            // 调用解密方法获取ssv和rand
            auto decrypted_pair = KmcEncryptGmk::DecryptSsvAndRand(encrypted_data);
            gmk_info.ssv = decrypted_pair.first;
            gmk_info.rand = decrypted_pair.second;
        }
        
        gmk_info.expireTime = GetStringColumn(stmt, 7);
        gmk_info.activateTime = GetStringColumn(stmt, 8);

        gmk_infos.push_back(gmk_info);
    }

    FinalizeStatement(stmt);
    
    if (result != SQLITE_DONE) {
        kmclog_e(LOG_TAG, "Error while querying GMK info: %s", sqlite3_errmsg(conn->GetHandle()));
        return false;
    }

    kmclog_i(LOG_TAG, "Successfully queried %zu GMK records for user: %s, group: %s", 
             gmk_infos.size(), user_uri.c_str(), group_id.c_str());
    
    return true;
}

bool SqliteDatabase::QueryGmkInfoByUser(const std::string& user_uri, std::vector<GmkInfo>& gmk_infos) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for querying gmk info by user");
        return false;
    }

    const std::string sql = R"(
        SELECT id, e_tag, gmk_id, user_uri, group_id, guk_id, encrypted_data, expire_time, activate_time
        FROM gmk_table WHERE user_uri = ?
        ORDER BY id
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, user_uri)) {
        FinalizeStatement(stmt);
        return false;
    }

    gmk_infos.clear(); // 清空输出vector
    
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        GmkInfo gmk_info;
        gmk_info.id = static_cast<uint64_t>(GetInt64Column(stmt, 0));
        gmk_info.eTag = GetStringColumn(stmt, 1);
        gmk_info.gmkId = GetStringColumn(stmt, 2);
        gmk_info.userUri = GetStringColumn(stmt, 3);
        gmk_info.groupId = GetStringColumn(stmt, 4);
        gmk_info.gukId = GetStringColumn(stmt, 5);
        
        // 获取加密数据并解密
        std::string encrypted_data = GetStringColumn(stmt, 6);
        if (!encrypted_data.empty()) {
            // 调用解密方法获取ssv和rand
            auto decrypted_pair = KmcEncryptGmk::DecryptSsvAndRand(encrypted_data);
            gmk_info.ssv = decrypted_pair.first;
            gmk_info.rand = decrypted_pair.second;
        }
        
        gmk_info.expireTime = GetStringColumn(stmt, 7);
        gmk_info.activateTime = GetStringColumn(stmt, 8);

        gmk_infos.push_back(gmk_info);
    }

    FinalizeStatement(stmt);
    
    if (result != SQLITE_DONE) {
        kmclog_e(LOG_TAG, "Error while querying GMK info by user: %s", sqlite3_errmsg(conn->GetHandle()));
        return false;
    }

    kmclog_i(LOG_TAG, "Successfully queried %zu GMK records for user: %s", 
             gmk_infos.size(), user_uri.c_str());
    
    return true;
}

bool SqliteDatabase::DeleteGmkInfoByUserGroup(const std::string& user_uri, const std::string& group_id) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for deleting gmk info by user group");
        return false;
    }

    const std::string sql = "DELETE FROM gmk_table WHERE user_uri = ? AND group_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, user_uri);
    success &= BindStringParam(stmt, 2, group_id);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to delete gmk info by user group: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "GMK info deleted by user group successfully");
        }
    }

    FinalizeStatement(stmt);
    return success;
}

// Raw GMK表操作实现
bool SqliteDatabase::InsertRawGmkInfo(const RawGmkInfo& raw_gmk_info) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for inserting raw gmk info");
        return false;
    }

    const std::string sql = R"(
        INSERT OR REPLACE INTO raw_gmk_table 
        (user_uri, group_id, gms_uri, e_tag, gmkMikey) 
        VALUES (?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, raw_gmk_info.userUri);
    success &= BindStringParam(stmt, 2, raw_gmk_info.groupId);
    success &= BindStringParam(stmt, 3, raw_gmk_info.gmsUri);
    success &= BindStringParam(stmt, 4, raw_gmk_info.eTag);
    success &= BindStringParam(stmt, 5, raw_gmk_info.gmkMikey);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to insert raw gmk info: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "Raw GMK info inserted successfully");
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::QueryRawGmkInfo(const std::string& user_uri, const std::string& group_id, RawGmkInfo& raw_gmk_info) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for querying raw gmk info");
        return false;
    }

    const std::string sql = R"(
        SELECT user_uri, group_id, gms_uri, e_tag, gmkMikey
        FROM raw_gmk_table WHERE user_uri = ? AND group_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, user_uri) || !BindStringParam(stmt, 2, group_id)) {
        FinalizeStatement(stmt);
        return false;
    }

    bool found = false;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        raw_gmk_info.userUri = GetStringColumn(stmt, 0);
        raw_gmk_info.groupId = GetStringColumn(stmt, 1);
        raw_gmk_info.gmsUri = GetStringColumn(stmt, 2);
        raw_gmk_info.eTag = GetStringColumn(stmt, 3);
        raw_gmk_info.gmkMikey = GetStringColumn(stmt, 4);

        found = true;
    }

    FinalizeStatement(stmt);
    return found;
}

bool SqliteDatabase::QueryRawGmkInfo(const std::string &user_uri,
									 const std::string &group_id,
									 const std::string	e_tag,
									 RawGmkInfo		&raw_gmk_info)
{
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for querying raw gmk info");
        return false;
    }

    const std::string sql = R"(
        SELECT user_uri, group_id, gms_uri, e_tag, gmkMikey
        FROM raw_gmk_table WHERE user_uri = ? AND group_id = ? AND e_tag = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    if (!BindStringParam(stmt, 1, user_uri) || !BindStringParam(stmt, 2, group_id) || !BindStringParam(stmt, 3, e_tag)) {
        FinalizeStatement(stmt);
        return false;
    }

    bool found = false;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        raw_gmk_info.userUri = GetStringColumn(stmt, 0);
        raw_gmk_info.groupId = GetStringColumn(stmt, 1);
        raw_gmk_info.gmsUri = GetStringColumn(stmt, 2);
        raw_gmk_info.eTag = GetStringColumn(stmt, 3);
        raw_gmk_info.gmkMikey = GetStringColumn(stmt, 4);

        found = true;
    }

    FinalizeStatement(stmt);
    return found;
}

bool SqliteDatabase::UpdateRawGmkInfo(const std::string& user_uri, const std::string& group_id, const std::string e_tag, const RawGmkInfo& raw_gmk_info) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for updating raw gmk info");
        return false;
    }

    const std::string sql = R"(
        UPDATE raw_gmk_table 
        SET gms_uri = ?, e_tag = ?, gmkMikey = ?
        WHERE user_uri = ? AND group_id = ? And e_tag = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, raw_gmk_info.gmsUri);
    success &= BindStringParam(stmt, 2, raw_gmk_info.eTag);
    success &= BindStringParam(stmt, 3, raw_gmk_info.gmkMikey);
    success &= BindStringParam(stmt, 4, user_uri);
    success &= BindStringParam(stmt, 5, group_id);
    success &= BindStringParam(stmt, 5, e_tag);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to update raw gmk info: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "Raw GMK info updated successfully");
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::DeleteRawGmkInfo(const std::string& user_uri, const std::string& group_id) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for deleting raw gmk info");
        return false;
    }

    const std::string sql = "DELETE FROM raw_gmk_table WHERE user_uri = ? AND group_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, user_uri);
    success &= BindStringParam(stmt, 2, group_id);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to delete raw gmk info: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "Raw GMK info deleted successfully");
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::DeleteRawGmkInfo(const std::string& user_uri, const std::string& group_id, std::string e_tag) {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for deleting raw gmk info");
        return false;
    }

    const std::string sql = "DELETE FROM raw_gmk_table WHERE user_uri = ? AND group_id = ? AND e_tag = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!PrepareStatement(sql, &stmt, *conn)) {
        return false;
    }

    bool success = true;
    success &= BindStringParam(stmt, 1, user_uri);
    success &= BindStringParam(stmt, 2, group_id);
    success &= BindStringParam(stmt, 3, e_tag);

    if (success) {
        int result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            kmclog_e(LOG_TAG, "Failed to delete raw gmk info: %s", sqlite3_errmsg(conn->GetHandle()));
        } else {
            kmclog_i(LOG_TAG, "Raw GMK info deleted successfully");
        }
    }

    FinalizeStatement(stmt);
    return success;
}

bool SqliteDatabase::ClearAllTables() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for clearing all tables");
        return false;
    }

    SqliteTransaction transaction(*conn);
    if (!transaction.Begin()) {
        kmclog_e(LOG_TAG, "Failed to begin transaction for clearing all tables");
        return false;
    }

    // 清空所有表的SQL语句
    const std::vector<std::string> clear_sql = {
        "DELETE FROM cert_table;",
        "DELETE FROM key_material_table;", 
        "DELETE FROM gmk_table;",
        "DELETE FROM raw_gmk_table;"
    };

    char* error_msg = nullptr;
    sqlite3* db = conn->GetHandle();

    for (const auto& sql : clear_sql) {
        int result = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &error_msg);
        if (result != SQLITE_OK) {
            kmclog_e(LOG_TAG, "Failed to execute clear SQL: %s, Error: %s", 
                    sql.c_str(), error_msg ? error_msg : "Unknown error");
            if (error_msg) {
                sqlite3_free(error_msg);
            }
            transaction.Rollback();
            return false;
        }
    }

    if (!transaction.Commit()) {
        kmclog_e(LOG_TAG, "Failed to commit clear all tables transaction");
        return false;
    }

    kmclog_i(LOG_TAG, "All database tables cleared successfully");
    return true;
}

bool SqliteDatabase::ClearCertTable() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for clearing cert table");
        return false;
    }

    const std::string sql = "DELETE FROM cert_table;";
    
    char* error_msg = nullptr;
    int result = sqlite3_exec(conn->GetHandle(), sql.c_str(), nullptr, nullptr, &error_msg);
    
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to clear cert table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    kmclog_i(LOG_TAG, "Cert table cleared successfully");
    return true;
}

bool SqliteDatabase::ClearKeyTable() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for clearing key table");
        return false;
    }

    const std::string sql = "DELETE FROM key_material_table;";
    
    char* error_msg = nullptr;
    int result = sqlite3_exec(conn->GetHandle(), sql.c_str(), nullptr, nullptr, &error_msg);
    
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to clear key material table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    kmclog_i(LOG_TAG, "Key material table cleared successfully");
    return true;
}

bool SqliteDatabase::ClearGmkTable() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for clearing gmk table");
        return false;
    }

    const std::string sql = "DELETE FROM gmk_table;";
    
    char* error_msg = nullptr;
    int result = sqlite3_exec(conn->GetHandle(), sql.c_str(), nullptr, nullptr, &error_msg);
    
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to clear gmk table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    kmclog_i(LOG_TAG, "GMK table cleared successfully");
    return true;
}

bool SqliteDatabase::ClearRawGmkTable() {
    auto conn = GetConnection();
    if (!conn) {
        kmclog_e(LOG_TAG, "Failed to get connection for clearing raw gmk table");
        return false;
    }

    const std::string sql = "DELETE FROM raw_gmk_table;";
    
    char* error_msg = nullptr;
    int result = sqlite3_exec(conn->GetHandle(), sql.c_str(), nullptr, nullptr, &error_msg);
    
    if (result != SQLITE_OK) {
        kmclog_e(LOG_TAG, "Failed to clear raw gmk table: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    kmclog_i(LOG_TAG, "Raw GMK table cleared successfully");
    return true;
}

// SqliteTransaction 实现
SqliteTransaction::SqliteTransaction(PooledConnection& conn) 
    : m_conn(conn), m_active(false), m_committed(false) {
}

SqliteTransaction::~SqliteTransaction() {
    if (m_active && !m_committed) {
        Rollback();
    }
}

bool SqliteTransaction::Begin() {
    if (m_active) {
        return false;
    }

    char* error_msg = nullptr;
    int result = sqlite3_exec(m_conn.GetHandle(), "BEGIN TRANSACTION", nullptr, nullptr, &error_msg);
    
    if (result == SQLITE_OK) {
        m_active = true;
        return true;
    } else {
        kmclog_e(LOG_TAG, "Failed to begin transaction: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }
}

bool SqliteTransaction::Commit() {
    if (!m_active || m_committed) {
        return false;
    }

    char* error_msg = nullptr;
    int result = sqlite3_exec(m_conn.GetHandle(), "COMMIT", nullptr, nullptr, &error_msg);
    
    if (result == SQLITE_OK) {
        m_committed = true;
        m_active = false;
        return true;
    } else {
        kmclog_e(LOG_TAG, "Failed to commit transaction: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }
}

bool SqliteTransaction::Rollback() {
    if (!m_active) {
        return false;
    }

    char* error_msg = nullptr;
    int result = sqlite3_exec(m_conn.GetHandle(), "ROLLBACK", nullptr, nullptr, &error_msg);
    
    m_active = false;
    
    if (result == SQLITE_OK) {
        return true;
    } else {
        kmclog_e(LOG_TAG, "Failed to rollback transaction: %s", 
                error_msg ? error_msg : "Unknown error");
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }
}

} // namespace KMC
