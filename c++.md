# Google C++ 风格
## 头文件声明顺序
```
// myproject/mycomponent/myclass.cc

#include "myproject/mycomponent/myclass.h"  // 优先包含当前模块头文件

#include <cstddef>      // C系统头文件
#include <cstring>

#include <string>       // C++标准库头文件
#include <vector>

#include <absl/strings/str_cat.h>  // 其他库的头文件
#include <glog/logging.h>

#include "myproject/base/error.h"  // 项目内头文件
#include "myproject/util/status.h"
```
## CMAKE
```
target_include_directories(
        ${kmc_library_name}
        SYSTEM PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl
        ${CMAKE_CURRENT_SOURCE_DIR}/include/curl
        ${CMAKE_CURRENT_SOURCE_DIR}/include/sqlite
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kmc
        ${CMAKE_CURRENT_SOURCE_DIR}/include/srtp2
)
#这样写可以用<>引用三方库的头文件

#共享库编译必须指定-fPIC参数，并且这个共享库里面的依赖三方库也必须指定-fPIC参数，否则不能生成动态库,因此最好，无论你编译的是静态库还是动态库
#都指定-fPIC参数
set(CMAKE_POSITION_INDEPENDENT_CODE ON)	全局生效
或者通过命令 cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..  全局生效
```

## Sqlite3
```
登录：sqlite3 数据库文件名.db

列出所有表：.tables

查看表结构：.schema 表名

SELECT * FROM 表名;

 退出sqlite3：.exit:

```

## 函数返回值的注意点
```
std::vector<int> createVector() {
    std::vector<int> local = {1, 2, 3};
    return local;         // 依赖RVO（推荐）
    // return std::move(local); // 显式移动（抑制RVO，不推荐）
}
如果再函数中定义了一个局部变量需要作为返回值返回，尤其是容器一类的，最好放到std::move()再返回，因为这个是一般编译器内部也会做的优化，但如果编译器没做这个优化就会报错，不过这个也看情况吧，能加也可以不加，主要为了加深理解
另外注意下：
std::vector<int>& processVector(std::vector<int>& a) {
    a.push_back(42);
    return std::move(a);  // 错误！
}
这样的话容易出问题
再调用的时候
std::vector<int> vec = {1, 2, 3};
auto& result = processVector(vec);  // vec被移动，此时vec变为空！
调用方法后会把vec置空，后续在使用就会出问题。
```
