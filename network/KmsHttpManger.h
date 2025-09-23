#ifndef KMSHTTPMANAGER_H_
#define KMSHTTPMANAGER_H_

#include <functional>
#include <memory>
#include <string>
#include <iostream>
#include <string>

#include <curl/curl.h>

#include "KmsRequest.h"
#include "KmsResponse.h"

namespace KMC {


// 内存缓冲区类
class MemoryBuffer {
public:
	std::unique_ptr<char[]> memory;
	size_t size = 0;
	size_t capacity = 0;

	void Resize(size_t new_size);
	void Append(const void *data, size_t append_size);
};

// HTTP写回调函数类型
using HttpWriteCallback = std::function<size_t(void *, size_t, size_t, void *)>;

// 通用HTTP管理器类
class CommHttpManager : public std::enable_shared_from_this<CommHttpManager> {
public:
	typedef std::shared_ptr<CommHttpManager> ptr;
	//证书路径先暂时不传
	CommHttpManager(std::string httpsCertPath = "");
	~CommHttpManager();

	// 核心HTTP请求方法
	HttpRequestResult ExecuteHttpsRequest(const std::string &url,
										  const std::string &authorization_token,
										  const std::string &post_data);

	// 设置写回调暂 时不使用
	void SetWriteCallback(HttpWriteCallback callback);

private:
	// 初始化和清理
	bool InitializeCurl();
	void CleanupCurl();

	// 设置HTTPS选项
	void SetupHttpsOptions();

	// 设置证书验证
	void SetupCertificateVerification();

	// 静态回调函数 暂时不使用
	static size_t DefaultWriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

	// 错误处理
	KmsErrorType MapCurlErrorToKmsError(CURLcode curl_code, long response_code);

	std::string m_httpsCertPath; // HTTPS证书路径
	CURL *m_curlHandle;
	HttpWriteCallback write_callback_;
};


} //KMC

#endif // KMSHTTPMANAGER_H_