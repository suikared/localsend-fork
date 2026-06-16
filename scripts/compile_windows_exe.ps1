cd app

flutter clean
flutter pub get
flutter build windows

Remove-Item "D:\inno" -Force  -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "D:\inno"
Copy-Item -Path "build\windows\x64\runner\Release\*" -Destination "D:\inno" -Recurse
Copy-Item -Path "assets\packaging\logo.ico" -Destination "D:\inno"

cd ..

Copy-Item -Path "scripts\windows\x64\*" -Destination "D:\inno" -Recurse
Remove-Item "D:\inno-result" -Force  -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "D:\inno-result"

# ponytail: locate iscc — PATH first, then common winget per-user/machine install dirs
$iscc = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
  $candidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
  ) | Where-Object { Test-Path $_ }
  $iscc = $candidates | Select-Object -First 1
}
if (-not $iscc) { throw "iscc (Inno Setup) not found. Install via: winget install JRSoftware.InnoSetup" }
& $iscc .\scripts\compile_windows_exe-inno-unsigned.iss

Write-Output 'Generated Windows exe installer!'
