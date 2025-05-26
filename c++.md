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
