# build.ps1 - Build script for PasswordRotator v0.0.2
Write-Host "Building PasswordRotator v0.0.2..." -ForegroundColor Cyan

$frameworkDir = "${env:windir}\Microsoft.NET\Framework64\v4.0.30319"
if (!(Test-Path $frameworkDir)) {
    $frameworkDir = "${env:windir}\Microsoft.NET\Framework\v4.0.30319"
}
if (!(Test-Path $frameworkDir)) {
    Write-Host "ERROR: .NET Framework 4.0+ not found" -ForegroundColor Red
    exit 1
}

$csc = Join-Path $frameworkDir "csc.exe"
if (!(Test-Path $csc)) {
    Write-Host "ERROR: csc.exe not found at $csc" -ForegroundColor Red
    exit 1
}

$outDir = "./releases/0.0.2"
if (!(Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

Write-Host "Using csc from: $csc" -ForegroundColor Yellow

# Compile with csc and embed manifest
Write-Host "Compiling PasswordRotator..." -ForegroundColor Yellow
& $csc /nologo /target:exe /out:"$outDir\PasswordRotator.exe" /platform:anycpu /optimize+ /debug:pdbonly /define:"TRACE" /win32manifest:"PasswordRotator.exe.manifest" /reference:"System.dll" /reference:"System.Core.dll" NativeMethods.cs Program.cs

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build completed successfully!" -ForegroundColor Green
    Write-Host "Executable is located at: $outDir\PasswordRotator.exe" -ForegroundColor Cyan
    Write-Host "File size: $((Get-Item "$outDir\PasswordRotator.exe").Length) bytes" -ForegroundColor Cyan
} else {
    Write-Host "Build failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}