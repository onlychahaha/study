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
##CMAKE
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
```
