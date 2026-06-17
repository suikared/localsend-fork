# Run @Tags(['security']) tests + key regression guards.
# app is a Flutter package -> flutter test; common is pure Dart -> dart test.
$ErrorActionPreference = 'Continue'
$root = Resolve-Path "$PSScriptRoot/../.."

Write-Host "== security tests: common (dart test) ==" -ForegroundColor Cyan
Push-Location "$root/common"
try {
    dart test test/unit/security -t security 2>&1
    $commonCode = $LASTEXITCODE
} finally { Pop-Location }

Write-Host "== security tests: app (flutter test) ==" -ForegroundColor Cyan
Push-Location "$root/app"
try {
    flutter test test/unit/security test/unit/util/rhttp_progress_test.dart 2>&1
    $appCode = $LASTEXITCODE
} finally { Pop-Location }

if ($appCode -ne 0 -or $commonCode -ne 0) {
    Write-Host "SECURITY TESTS FAILED (app=$appCode common=$commonCode)" -ForegroundColor Red
    exit 1
}
Write-Host "SECURITY TESTS PASSED" -ForegroundColor Green
exit 0
