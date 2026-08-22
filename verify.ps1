# verify.ps1 - one-shot verification: HEAD check + clean build + full ctest.
# Usage: pwsh verify.ps1 [-Clean]
#   -Clean  rebuild from scratch in a fresh build-verify-<ts> directory.
# Uses an isolated build dir per run so concurrent sessions never share
# half-rebuilt artifacts (mixed-version exes caused false regressions).

param([switch]$Clean)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$buildDir = if ($Clean) { Join-Path $root "build-verify-$stamp" } else { Join-Path $root "build-verify" }

Write-Host "== HEAD =="
git -C $root rev-parse HEAD
Write-Host "== workspace (excluding .opencode state) =="
git -C $root status --porcelain | Where-Object { $_ -notmatch "^ M \.opencode/" }

Write-Host "== configure =="
cmake -S $root -B $buildDir -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_PLUGINS=ON -DXTCP_BUILD_BENCH=OFF
if ($LASTEXITCODE -ne 0) { Write-Error "configure failed"; exit 1 }

Write-Host "== build =="
cmake --build $buildDir --config Release
if ($LASTEXITCODE -ne 0) { Write-Error "build failed"; exit 1 }

Write-Host "== ctest =="
ctest --test-dir $buildDir -C Release --output-on-failure
exit $LASTEXITCODE
