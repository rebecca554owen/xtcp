# Building

> Language: **English** | [中文](BUILDING_CN.md)

Platform and toolchain coverage, per-platform recipes, sanitizer builds,
and the ARM64 cross-verification lab. Chinese version:
[BUILDING_CN.md](BUILDING_CN.md). Option semantics live in
[USAGE.md](USAGE.md) §1.

## 1. Supported platforms

| Platform | Toolchain | Status |
|---|---|---|
| Windows x86/x64 | MSVC 14.39 (Visual Studio 2022) | First-class: full test suite runs here |
| Linux x86_64 | GCC 13, Clang (any recent) | First-class: CI runs the suite under ASan+UBSan with both compilers |
| Android | NDK r24+, ABIs arm64-v8a / armeabi-v7a / x86 / x86_64 | Cross-compiles clean; NEON checksums used on arm64 |
| ARM64 Linux | aarch64-linux-gnu-GCC 13 + qemu-aarch64 | Full suite verified under emulation |

Requirements: CMake ≥ 3.16, a C++17 compiler, C11 compiler for the
reference plugin cores. No external dependencies for the core library;
lwIP differential testing vendors its own lwIP when enabled.

## 2. Linux (GCC or Clang)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON -DXTCP_BUILD_SAMPLES=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

TUN-based interop samples additionally need root at runtime
(`/dev/net/tun`); they do not affect the build.

## 3. Windows (MSVC)

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64 \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Notes:

- The interop samples are excluded by design (`UNIX AND NOT APPLE` guard);
  everything else builds identically.
- `XTCP_SANITIZE=ON` uses the MSVC CRT leak detector here; ASan/UBSan are
  the Linux path.
- A MinGW/clang-windows build compiles but its ASan runtime is broken
  upstream; treat it as unsupported for sanitizer work.

## 4. Android NDK

```bash
cmake -B build-ndk -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DXTCP_BUILD_TESTS=ON
cmake --build build-ndk
```

Repeat per ABI (`armeabi-v7a`, `x86`, `x86_64`). arm64-v8a gets the NEON
checksum path automatically (runtime-detected); other ABIs use the scalar
path. Tests run on-device or via emulator; there is no QEMU recipe for
Android binaries.

## 5. Sanitizer builds (Linux)

```bash
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug \
      -DXTCP_SANITIZE=ON -DXTCP_BUILD_TESTS=ON
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure
```

This is what CI runs (both clang++ and g++). Leak-free and crash-free is a
merge gate; the suite also asserts pool/quota balance per test cycle, which
catches most leaks before sanitizers do.

## 6. ARM64 cross-verification lab (Linux host)

The stack is verified on a second architecture without ARM hardware:

```bash
# One-time: install cross toolchain + user-mode emulator
sudo apt install g++-13-aarch64-linux-gnu qemu-user

# Configure out-of-tree, fully static so qemu needs no sysroot
cmake -B ~/xtcp-arm -S /path/to/xtcp \
  -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
  -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_PLUGINS=OFF \
  -DXTCP_BUILD_BENCH=OFF -DXTCP_BUILD_LWIP=OFF \
  -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build ~/xtcp-arm -j$(nproc)

# Run each test binary under emulation
qemu-aarch64 ~/xtcp-arm/test_tcp_fsm
```

Observed behavior worth knowing before you rely on this lab:

- Test binaries land flat in the build directory (`~/xtcp-arm/test_*`),
  not in a `tests/` subdirectory.
- Timing-sensitive tests need their deadlines relaxed under single-core
  emulation; the suite accounts for this, but wall-clock numbers from QEMU
  are meaningless as performance data (see PERFORMANCE.md §1).
- Building on a network filesystem is slow; keep the build directory on a
  local filesystem.

## 7. Continuous integration

`.github/workflows/ci.yml` runs three jobs on every push:

1. **Windows (MSVC)** — configure, build, full `ctest`.
2. **Linux (clang++)** — ASan+UBSan build, full `ctest`.
3. **Linux (g++)** — ASan+UBSan build, full `ctest`.

A change merges only when all three are green. The QEMU lab above is not
part of CI (no ARM runners); it is executed manually per release.
