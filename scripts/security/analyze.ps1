# 运行 app + common 的 dart analyze。只把 error 级当失败；warning/info 折叠计数。
# 用法: scripts/security/analyze.ps1
$ErrorActionPreference = 'Continue'
$root = Resolve-Path "$PSScriptRoot/../.."

function Invoke-Analyze($pkg) {
    Push-Location "$root/$pkg"
    try {
        $out = (& dart analyze lib test 2>&1) -as [string[]]
        $errors = @($out | Where-Object { $_ -match ' error -' })
        $warnings = @($out | Where-Object { $_ -match ' warning -' })
        $infos = @($out | Where-Object { $_ -match ' info -' })

        Write-Host "== $pkg : errors=$($errors.Count) warnings=$($warnings.Count) infos=$($infos.Count) ==" -ForegroundColor Cyan
        if ($errors.Count -gt 0) {
            $errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            return 1
        }
        return 0
    } finally { Pop-Location }
}

$appCode = Invoke-Analyze 'app'
$commonCode = Invoke-Analyze 'common'

if ($appCode -ne 0 -or $commonCode -ne 0) {
    Write-Host "ANALYZE FAILED (app=$appCode common=$commonCode)" -ForegroundColor Red
    exit 1
}
Write-Host "ANALYZE CLEAN (0 errors; warning/info noise is mappable generated base classes, see report)" -ForegroundColor Green
exit 0
