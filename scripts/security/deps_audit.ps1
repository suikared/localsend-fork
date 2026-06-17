# 依赖审查：pub outdated + 关键安全包列出。
# 用法: scripts/security/deps_audit.ps1
$ErrorActionPreference = 'Continue'
$root = Resolve-Path "$PSScriptRoot/../.."

foreach ($pkg in @('app', 'common')) {
    Write-Host "== pub outdated: $pkg ==" -ForegroundColor Cyan
    Push-Location "$root/$pkg"
    try {
        dart pub outdated 2>&1
        Write-Host "-- 直接依赖（安全相关）--" -ForegroundColor Cyan
        dart pub deps --no-dev 2>&1 | Select-String -Pattern 'rhttp|shelf|crypto|uuid|encrypt|tls|http|rust_bridge'
    } finally { Pop-Location }
    Write-Host ""
}

Write-Host "Next: search known CVEs for the listed packages (WebSearch/Context7), fill into doc/security-audit-report.md" -ForegroundColor Cyan
