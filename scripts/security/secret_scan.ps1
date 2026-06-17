# 高置信密钥扫描。退出码 1 = 发现疑似密钥。
# 扫描 app/lib, common/lib, app/rust/src（排除生成文件与多语言字符串 gen）。
$ErrorActionPreference = 'Continue'
$root = Resolve-Path "$PSScriptRoot/../.."

$patterns = @(
    '-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----',
    'AKIA[0-9A-Z]{16}',
    'gh[pousr]_[A-Za-z0-9]{36}',
    'sk-[A-Za-z0-9]{20,}',
    'xox[baprs]-[A-Za-z0-9-]{10,}',
    '(?i)api[_-]?key\s*[:=]\s*[''"][A-Za-z0-9_\-]{32,}[''"]'
)
$regex = ($patterns -join '|')
$hits = 0

$dirs = @("$root/app/lib", "$root/common/lib", "$root/app/rust/src")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Recurse -File -Include *.dart,*.rs,*.yaml,*.json,*.toml -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\(gen|generated|\.gen|frb_generated)' } |
      ForEach-Object {
        $f = $_
        $i = 0
        foreach ($line in Get-Content $f.FullName) {
            $i++
            if ($line -match $regex) {
                Write-Host ("{0}:{1} : {2}" -f $f.FullName.Replace($root, ''), $i, $line.Trim()) -ForegroundColor Yellow
                $hits++
            }
        }
    }
}

if ($hits -gt 0) {
    Write-Host "SECRET SCAN: $hits 疑似命中（人工复核）" -ForegroundColor Red
    exit 1
}
Write-Host "SECRET SCAN CLEAN" -ForegroundColor Green
exit 0
