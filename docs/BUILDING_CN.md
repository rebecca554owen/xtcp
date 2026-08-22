# 构建

> 语言：[English](BUILDING.md) | **中文**

平台与工具链覆盖、各平台配方、sanitizer 构建、ARM64 交叉验证环境。英文
主版本：[BUILDING.md](BUILDING.md)。选项语义见 [USAGE_CN.md](USAGE_CN.md) §1。

## 1. 支持的平台

| 平台 | 工具链 | 状态 |
|---|---|---|
| Windows x86/x64 | MSVC 14.39（Visual Studio 2022） | 一等公民：全量测试套件在此运行 |
| Linux x86_64 | GCC 13、Clang（近期任意版本） | 一等公民：CI 以 ASan+UBSan 双编译器运行全量套件 |
| Android | NDK r24+，ABI arm64-v8a / armeabi-v7a / x86 / x86_64 | 交叉编译零错误；arm64 使用 NEON 校验和 |
| ARM64 Linux | aarch64-linux-gnu-GCC 13 + qemu-aarch64 | 全量套件在仿真下验证通过 |

要求：CMake ≥ 3.16、C++17 编译器、参考插件核心所需的 C11 编译器。核心库
无外部依赖；lwIP 差分测试在启用时自带 vendored lwIP。

## 2. Linux（GCC 或 Clang）

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON -DXTCP_BUILD_SAMPLES=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

基于 TUN 的互操作样例在运行时另需 root（`/dev/net/tun`）；不影响构建。

## 3. Windows（MSVC）

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64 \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

说明：

- 互操作样例按设计被排除（`UNIX AND NOT APPLE` 守卫）；其余构建完全一致。
- `XTCP_SANITIZE=ON` 在此使用 MSVC CRT 泄漏检测；ASan/UBSan 是 Linux 路径。
- MinGW/clang-windows 可编译，但其 ASan 运行时上游已损坏；sanitizer 工作
  请视为不支持该组合。

## 4. Android NDK

```bash
cmake -B build-ndk -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DXTCP_BUILD_TESTS=ON
cmake --build build-ndk
```

按 ABI 重复（`armeabi-v7a`、`x86`、`x86_64`）。arm64-v8a 自动获得 NEON
校验和路径（运行时探测）；其他 ABI 走标量路径。测试在真机或模拟器上运行；
Android 二进制没有 QEMU 配方。

## 5. Sanitizer 构建（Linux）

```bash
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug \
      -DXTCP_SANITIZE=ON -DXTCP_BUILD_TESTS=ON
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure
```

这正是 CI 运行的内容（clang++ 与 g++ 双份）。零泄漏零崩溃是合并门；套件
还在每个测试周期断言池/配额平衡，多数泄漏在 sanitizer 之前就会被抓住。

## 6. ARM64 交叉验证环境（Linux 主机）

无需 ARM 硬件即可在第二架构上验证协议栈：

```bash
# 一次性：安装交叉工具链 + 用户态仿真器
sudo apt install g++-13-aarch64-linux-gnu qemu-user

# 树外配置，全静态链接使 qemu 无需 sysroot
cmake -B ~/xtcp-arm -S /path/to/xtcp \
  -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_PLUGINS=OFF \
  -DXTCP_BUILD_BENCH=OFF -DXTCP_BUILD_LWIP=OFF \
  -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build ~/xtcp-arm -j$(nproc)

# 在仿真下逐个运行测试二进制
qemu-aarch64 ~/xtcp-arm/test_tcp_fsm
```

依赖该环境前值得了解的实测行为：

- 测试二进制平铺在构建目录根部（`~/xtcp-arm/test_*`），不在 `tests/`
  子目录。
- 时序敏感测试在单核仿真下需要放宽截止时间；套件已为此设计，但 QEMU 的
  墙钟数字作为性能数据毫无意义（见 PERFORMANCE_CN.md §1）。
- 网络文件系统上构建很慢；构建目录请放在本地文件系统。

## 7. 持续集成

`.github/workflows/ci.yml` 在每次推送时运行三个作业：

1. **Windows (MSVC)** —— 配置、构建、全量 `ctest`。
2. **Linux (clang++)** —— ASan+UBSan 构建、全量 `ctest`。
3. **Linux (g++)** —— ASan+UBSan 构建、全量 `ctest`。

三者全绿才可合并。上面的 QEMU 环境不属于 CI（无 ARM runner），按发布节点
人工执行。
