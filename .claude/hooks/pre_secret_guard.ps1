# PreToolUse guard: block .dart writes that embed high-confidence secrets,
# or that exceed 800 lines. Reads the hook JSON payload on stdin.
# Exit 0 = allow, Exit 2 = block (message on stderr shown to Claude).
$ErrorActionPreference = 'Stop'
$raw = [Console]::In.ReadToEnd()

try {
    $data = $raw | ConvertFrom-Json
} catch {
    # Malformed payload: never block.
    exit 0
}

$ti = $data.tool_input
if ($null -eq $ti) { exit 0 }

$path = $ti.file_path
if ($null -ne $path -and $path -notmatch '\.dart$') { exit 0 }

# Collect the text we will scan: Write has content; Edit has old/new strings.
$text = ($ti.content)
if ($null -eq $text) { $text = "$($ti.old_string)`n$($ti.new_string)" }
if ([string]::IsNullOrEmpty($text)) { exit 0 }

# High-confidence secret patterns only (avoid false positives that would
# block legitimate edits).
$patterns = @(
    '-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----',
    'AKIA[0-9A-Z]{16}',
    'gh[pousr]_[A-Za-z0-9]{36}',
    'sk-[A-Za-z0-9]{20,}',
    '(?i)api[_-]?key\s*[:=]\s*[''"][A-Za-z0-9_\-]{32,}[''"]'
)

foreach ($p in $patterns) {
    if ($text -match $p) {
        [Console]::Error.WriteLine("[hook] BLOCKED:疑似硬编码密钥 ($($matches[0].Substring(0,[Math]::Min(12,$matches[0.Length))))...) in $path")
        [Console]::Error.WriteLine("[hook] 把密钥移到环境变量/密钥管理器。确认安全请临时禁用此 hook。")
        exit 2
    }
}

# Line-count guard (Write only, content present).
if ($null -ne $ti.content) {
    $lines = ($ti.content -split "`n").Length
    if ($lines -gt 800) {
        [Console]::Error.WriteLine("[hook] BLOCKED:文件 $path 超过 800 行 ($lines)。拆分为更小模块。")
        exit 2
    }
}

exit 0
