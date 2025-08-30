<<<<<<< HEAD
# Small Trace - 简单代码追踪工具

![Platform](https://img.shields.io/badge/platform-Android-green.svg)
![Language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue.svg)
![Framework](https://img.shields.io/badge/framework-Frida--Gum%20%7C%20QBDI-orange.svg)

## 项目介绍

随着软件逆向与安全研究的发展，越来越多的开发者和研究人员开始关注代码追踪。尽管市面上已有不少工具，但大多数都未开源，或者无法提供定制化的追踪功能。在此背景下，我决定利用几天时间开发一款简单的代码追踪工具。

**Small Trace** 借助前辈们的工作，结合 **QBDI** 与 **Frida** 的 **Gum** 模块，构建了一套功能强大的 **Native SO 库**。这套库专注于底层代码追踪功能，提供了完整的动态插桩、内存分析、系统调用监控等核心能力。

> **注意**: 项目中的 Android UI 部分仅用于功能测试，核心价值在于 Native SO 库的实现。

## 核心特性

### 🎯 Frida 集成脚本 (CalvinTrace.js)

```javascript
// 配置变量
var TraceSoPath = "/data/local/tmp/libqdbi.so";  // 用于存放目标so的路径
var SO_name = "libcheckqdbi.so";      // 目标SO的名称
var Symbol = "Java_io_calvin_checkqdbi_MainActivity_checkQDBI";       // 符号名
var so_offset = 0;     // SO中的偏移量
var Trace_Mode = 0;    // 跟踪模式 (0 - 符号追踪, 1 - 偏移量追踪)
var args = 2;       // trace 函数的参数 有几个？

// 外部声明的符号，将在加载TraceSoPath之后查找
var Calvin_Trace_symbol = null;
var Calvin_Trace_offset = null;

// 函数: 主动调用符号追踪或偏移量追踪
function traceSymbolOrOffset(soName, symbolName, addr, mode) {
    if (mode === 0) { // 符号追踪模式
        console.log(`开始符号追踪: ${soName} -> ${symbolName}`);
        // 获取符号地址（直接获取符号 Calvin_Trace_symbol）
        if (Calvin_Trace_symbol !== null) {
            var symbolFunc = new NativeFunction(Calvin_Trace_symbol, 'int', ['pointer', 'pointer', 'int']);
            // 主动调用 Calvin_Trace_symbol
            try {
                var agr1 = Memory.allocUtf8String(SO_name);
                var agr2 = Memory.allocUtf8String(symbolName);
                var result = symbolFunc(agr1, agr2, args); // 根据需求传入参数
                console.log(`符号 ${symbolName} 调用结果: ${result}`);
            } catch (e) {
                console.log("符号追踪失败: " + e);
            }
        } else {
            console.log(`Calvin_Trace_symbol 符号未找到`);
        }
    } else if (mode === 1) { // 偏移量追踪模式
        console.log(`开始偏移量追踪: ${soName} 地址: ${addr}`);
        // 获取符号的偏移量并转化为函数指针
        if (Calvin_Trace_offset !== null) {
            var offsetFunc = new NativeFunction(Calvin_Trace_offset, 'int', ['pointer', 'long', 'int']);
            // 主动调用 Calvin_Trace_offset
            try {
                var agr1 = Memory.allocUtf8String(SO_name);
                var result = offsetFunc(agr1, addr, 1); // 根据需求传入参数
                console.log(`偏移量地址: ${addr}, 调用结果: ${result}`);
            } catch (e) {
                console.log("偏移量追踪失败: " + e);
            }
        } else {
            console.log(`Calvin_Trace_offset 符号未找到`);
        }
    } else {
        console.log("无效的追踪模式");
    }
}
// 标志变量，确保 TraceSoPath 只加载一次
var isTraceSoLoaded = false;

// 等待目标SO加载
var android_dlopen_ext = Module.findExportByName('libc.so', 'android_dlopen_ext');
var traced_so = null;

// hook android_dlopen_ext 来等待目标so加载
Interceptor.attach(android_dlopen_ext, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path.indexOf(SO_name) !== -1) {
            console.log(`目标so加载中: ${SO_name}`);
            traced_so = path; // 记录目标so路径
        }
    },
    onLeave: function(retval) {
        // 在目标so加载完毕后加载TraceSoPath
        if (traced_so && !isTraceSoLoaded) {
            console.log(`目标so加载完毕，加载 TraceSoPath: ${TraceSoPath}`);
            try {
                // 加载 TraceSoPath
                var trace_so_handle = Module.load(TraceSoPath);
                console.log(`TraceSoPath已加载: ${trace_so_handle}`);

                // 设置标志，确保 TraceSoPath 只加载一次
                isTraceSoLoaded = true;

                // 加载完 TraceSoPath 后查找符号
                Calvin_Trace_symbol = Module.findExportByName(TraceSoPath, 'Calvin_Trace_symbol');
                Calvin_Trace_offset = Module.findExportByName(TraceSoPath, 'Calvin_Trace_offset');

                if (Calvin_Trace_symbol && Calvin_Trace_offset) {
                    console.log("符号和偏移量追踪函数已找到");

                    // 根据模式决定符号追踪还是偏移量追踪
                    if (Trace_Mode === 0) {
                        traceSymbolOrOffset(traced_so, Symbol, 0, Trace_Mode);  // 符号追踪
                    } else {
                        traceSymbolOrOffset(traced_so, "", so_offset, Trace_Mode);  // 偏移量追踪
                    }
                } else {
                    console.log("未能找到追踪函数");
                }
            } catch (e) {
                console.log("加载TraceSoPath失败: " + e);
            }
        }
    }
});
```

### 🔍 内存分析
- **QBDI (QuarkslaB Dynamic binary Instrumentation)** 集成
- 支持 ARM64 架构的指令级追踪
- 内存读写监控与 hexdump 展示
- 寄存器状态变化追踪

### 📊 系统调用分析
- **SVC (Supervisor Call)** 调用监控
- 系统调用参数解析
- 内核接口调用追踪

### 🛠 模块化设计
- 独立的 SO 库，可集成到任何 Android 项目
- 标准化的 C/C++ API 接口
- 最小化依赖，便于移植和集成

## 技术架构

```
┌─────────────────┐
│   Test UI       │  ← 测试界面 (仅用于验证)
│   (可选组件)     │
└─────────┬───────┘
          │ JNI (测试接口)
┌─────────▼───────┐
│   libqdbi.so    │  ← 核心 SO 库
│   (主要功能)     │
└─────────┬───────┘
          │
    ┌─────▼─────┐    ┌─────────────┐    ┌─────────────┐
    │ Frida-Gum │    │    QBDI     │    │  SVC Call   │
    │  (Hook)   │    │ (指令追踪)   │    │  (系统调用)  │
    └───────────┘    └─────────────┘    └─────────────┘
          │                  │                  │
    ┌─────▼─────┐    ┌─────────────┐    ┌─────────────┐
    │  Hook     │    │   Memory    │    │  Symbol     │
    │  Engine   │    │  Analysis   │    │  Resolver   │
    └───────────┘    └─────────────┘    └─────────────┘
```

## SO 库功能模块

### 1. Hook 引擎 (`hook/`)
- **gumx.c**: Frida-Gum 扩展功能
- 函数入口/出口动态拦截
- 参数和返回值实时捕获
- 支持多线程环境下的安全Hook

### 2. 核心追踪引擎 (`core/`)
- **core.c**: 底层追踪核心逻辑
- **gum_qbdi_bridge.cpp**: QBDI 与 Gum 的桥接层
- 指令级别的执行追踪
- 内存访问模式分析

### 3. 系统调用监控 (`svc_call/`)
- **svccall.c**: 系统调用包装器
- **svclibc.c**: libc 系统调用接口
- ARM64 SVC 指令拦截
- 内核态/用户态调用分析

### 4. 符号解析引擎 (`soinfo/`)
- **sosym_c.cpp**: SO 文件符号信息解析
- 动态链接符号查找
- 运行时地址映射
- PLT/GOT 表解析

## 快速开始

### 环境要求

- **开发环境**:
  - Android Studio 4.0+
  - Android NDK r21+
  - CMake 3.22.1+
  - Java JDK 8+

- **运行环境**:
  - Android 设备 (API Level 21+)
  - **Root 权限** (必需)
  - Frida 工具链
  - ADB 调试工具

### 构建步骤

1. **克隆项目**
```bash
git clone <repository-url>
cd qdbi
```

2. **编译 SO 库**
```bash
# 使用 Gradle 构建
./gradlew assembleDebug

# SO 库输出位置
# app/build/intermediates/cmake/debug/obj/arm64-v8a/libqdbi.so
```

3. **提取核心文件**
构建完成后，你需要：
- `libqdbi.so` - 从构建输出目录提取
- `CalvinTrace.js` - Frida 脚本文件

### SO 库使用方法

#### 1. **获取文件**
构建完成后，你将得到两个核心文件：
- `libqdbi.so` - 核心追踪动态库
- `CalvinTrace.js` - Frida 脚本配置文件

#### 2. **部署动态库**
将 SO 库部署到目标设备：

```bash
# 连接设备并获取 root 权限
adb shell
su
setenforce 0

# 将 SO 库推送到设备
adb push libqdbi.so /data/local/tmp/
```

> **⚠️ 重要**: 确保目标设备已 root，并允许应用程序访问 `/data/local/tmp/` 目录

#### 3. **配置追踪脚本**
在 `CalvinTrace.js` 文件中配置目标信息：

```javascript
// 追踪配置参数
var TraceSoPath = "/data/local/tmp/libqdbi.so";              // 追踪 SO 库路径
var SO_name = "libcheckqdbi.so";                           // 目标 SO 名称
var Symbol = "Java_io_calvin_checkqdbi_MainActivity_checkQDBI"; // 目标符号名
var so_offset = 0;                                         // SO 中的偏移量
var Trace_Mode = 0;    // 追踪模式: 0-符号追踪, 1-偏移量追踪
var args = 2;          // 目标函数参数数量
```

**配置说明**:
- `TraceSoPath`: libqdbi.so 在设备上的完整路径
- `SO_name`: 要追踪的目标 SO 库名称
- `Symbol`: 要 Hook 的函数符号名（符号追踪模式）
- `so_offset`: 函数在 SO 中的偏移地址（偏移追踪模式）
- `Trace_Mode`: 选择追踪方式（符号 vs 偏移）
- `args`: 目标函数的参数个数

#### 4. **启动追踪**
使用 Frida 启动目标应用并加载追踪脚本：

```bash
# 启动目标应用并注入追踪脚本
frida -U -f com.example.target -l CalvinTrace.js

# 或者附加到已运行的进程
frida -U com.example.target -l CalvinTrace.js  (你需要调整一下frida脚本)
```

#### 5. **查看追踪结果**
启动后，你可以：
- 📍 **定位加密解密操作**: 实时查看内存读写位置
- 🔍 **分析函数调用流程**: 跟踪函数参数和返回值
- 💾 **监控内存访问**: 观察关键数据的内存变化
- 🎯 **快速定位问题**: 轻松找到目标代码位置

#### 6. **测试验证 (可选)**
如果需要验证功能，可以使用项目中的测试 APK：
```bash
# 编译测试应用
./gradlew assembleDebug

# 安装到设备
adb install app/build/outputs/apk/debug/app-debug.apk
```

## 代码示例

### Frida-Gum Hook 示例

```c
// Hook open 函数
gum_interceptor_attach (interceptor,
    GSIZE_TO_POINTER (gum_module_find_global_export_by_name ("open")),
    listener,
    GSIZE_TO_POINTER (EXAMPLE_HOOK_OPEN),
    GUM_ATTACH_FLAGS_NONE);
```

### QBDI 指令追踪示例

```cpp
// 追踪函数执行
static QBDI::VMAction onPre(QBDI::VM* vm, QBDI::GPRState* g, QBDI::FPRState*, void* u){
    const QBDI::InstAnalysis* ia = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY);
    // 分析指令并记录状态变化
    return QBDI::VMAction::CONTINUE;
}
```

## 项目结构

```
qdbi/
├── app/                          # 主应用模块 (测试用)
│   ├── src/main/
│   │   ├── cpp/                  # ★ 核心 SO 库源码
│   │   │   ├── core/            # 追踪核心引擎
│   │   │   ├── hook/            # Hook 功能实现
│   │   │   ├── svc_call/        # 系统调用模块
│   │   │   ├── soinfo/          # 符号解析模块
│   │   │   ├── include/         # 头文件
│   │   │   ├── record/          # 记录相关
│   │   │   ├── lib/             # 静态库 (QBDI, Frida-Gum)
│   │   │   └── CMakeLists.txt   # CMake 构建配置
│   │   ├── java/                # 测试界面 (UI)
│   │   └── res/                 # 资源文件
│   └── build.gradle             # Gradle 构建脚本
├── ceshiQDBI/                   # 测试模块
└── README.md                    # 项目说明文档
```

### 📎 核心文件说明

#### SO 库核心文件
- **`CMakeLists.txt`**: 构建 libqdbi.so 的主配置
- **`native-lib.cpp`**: JNI 桥接层，提供测试接口
- **`core/gum_qbdi_bridge.cpp`**: QBDI 与 Frida-Gum 的融合层
- **`hook/gumx.c`**: Frida-Gum 扩展功能
- **`svc_call/svccall.c`**: ARM64 系统调用处理
- **`soinfo/sosym_c.cpp`**: ELF 符号表解析

#### 第三方依赖
- **`lib/libQBDI.a`**: QBDI 静态库
- **`lib/libfrida-gum.a`**: Frida-Gum 静态库

## 技术亮点

### 🔧 核心 SO 库构建

**主要产出**: `libqdbi.so` - 包含所有追踪功能的原生库

**构建特性**:
- 静态链接 QBDI 和 Frida-Gum
- 最小化运行时依赖
- 支持 ARM64 和 x86 架构
- 优化的二进制大小

### ⚡ 高性能追踪
- 最小化运行时开销
- 异步日志记录机制
- 智能内存管理

### 🛡️ 安全研究友好
- 支持加密字符串解密追踪
- 系统调用参数深度分析
- 内存布局可视化

## 应用场景

### 🔍 逆向工程
- **Native 代码行为分析**: 追踪 SO 库内部函数调用
- **算法逆向**: 观察加密/解密算法的执行流程
- **反调试绕过**: 动态修改反调试检测逻辑

### 🛡️ 安全研究
- **恶意软件分析**: 监控恶意 SO 库的行为模式
- **漏洞挖掘**: 追踪内存访问异常和边界检查
- **加固方案测试**: 验证代码保护措施的有效性

### ⚡ 性能分析
- **热点函数识别**: 统计函数调用频率和耗时
- **内存泄露检测**: 监控内存分配和释放
- **系统调用优化**: 分析系统调用的使用模式

## 注意事项

⚠️ **重要提醒**：
- **核心价值**: 本项目的核心是 Native SO 库，UI 部分仅用于功能验证
- **集成方式**: 可直接将 `libqdbi.so` 集成到任何 Android 项目中
- **权限要求**: 某些功能可能需要 root 权限或调试权限
- **平台兼容**: 不同 Android 版本和架构的兼容性可能有差异
- **使用目的**: 仅用于合法的安全研究和学习目的

## 开发计划

### 🛠️ SO 库功能增强
- [ ] 增加更多系统调用的支持 (mmap, ptrace, etc.)
- [ ] 实现更精细的内存访问分析
- [ ] 支持多线程并发追踪
- [ ] 增加批量 Hook 管理功能

### 🎦 性能优化
- [ ] 优化内存使用和性能开销
- [ ] 实现异步日志记录机制
- [ ] 增加追踪数据压缩存储

### 🔧 架构支持
- [ ] 支持更多架构 (ARM32, x86, x86_64)
- [ ] 增加 iOS 平台支持
- [ ] 实现跨平台统一 API

### 📊 数据导出
- [ ] 支持追踪数据导出 (JSON, Binary)
- [ ] 实现实时数据流传输
- [ ] 增加第三方工具集成接口

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 致谢

本项目基于以下优秀的开源项目：

- [Frida](https://frida.re/) - 动态插桩框架
- [QBDI](https://qbdi.quarkslab.com/) - 动态二进制插桩引擎
- [Android NDK](https://developer.android.com/ndk) - Android 原生开发工具包

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或建议，请通过以下方式联系：

- GitHub Issues: [提交问题](../../issues)
- Email: [1518936272@qq.com]

---

