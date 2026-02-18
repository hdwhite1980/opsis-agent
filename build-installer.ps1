# build-installer.ps1 - Build OPSIS Agent Installer
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OPSIS Agent Installer Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check if Inno Setup is installed
$innoPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $innoPath)) {
    Write-Host "ERROR: Inno Setup not found!" -ForegroundColor Red
    Write-Host "Download from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    exit 1
}
Write-Host "  + Inno Setup found" -ForegroundColor Green

# Check if WinSW self-contained binary exists
$winswPath = "tools\winsw\WinSW-x64.exe"
if (-not (Test-Path $winswPath)) {
    Write-Host "Downloading WinSW v2.12.0 self-contained x64..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path "tools\winsw" | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' -OutFile $winswPath -UseBasicParsing
        $size = [math]::Round((Get-Item $winswPath).Length / 1MB, 2)
        Write-Host "  + WinSW downloaded ($size MB)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download WinSW!" -ForegroundColor Red
        Write-Host "  Download manually from: https://github.com/winsw/winsw/releases/tag/v2.12.0" -ForegroundColor Yellow
        Write-Host "  Place WinSW-x64.exe in tools\winsw\" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "  + WinSW self-contained binary found" -ForegroundColor Green
}

# Check if VC++ Redistributable is present for bundling
$vcRedistPath = "tools\vc_redist.x64.exe"
if (-not (Test-Path $vcRedistPath)) {
    Write-Host "Downloading Visual C++ Redistributable x64..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -OutFile $vcRedistPath -UseBasicParsing
        $size = [math]::Round((Get-Item $vcRedistPath).Length / 1MB, 2)
        Write-Host "  + VC++ Redistributable downloaded ($size MB)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download VC++ Redistributable!" -ForegroundColor Red
        Write-Host "  Download manually from: https://aka.ms/vs/17/release/vc_redist.x64.exe" -ForegroundColor Yellow
        Write-Host "  Place vc_redist.x64.exe in tools\" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "  + VC++ Redistributable found" -ForegroundColor Green
}

# Check if icon exists
if (-not (Test-Path "assets\icon.ico")) {
    Write-Host "WARNING: assets\icon.ico not found" -ForegroundColor Yellow
    Write-Host "  Creating placeholder icon directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path "assets" | Out-Null
    Write-Host "  Please add icon.ico (256x256) to assets folder" -ForegroundColor Yellow
    Write-Host "  Converter: https://convertico.com" -ForegroundColor Cyan
}

# Check if LICENSE.txt exists
if (-not (Test-Path "LICENSE.txt")) {
    Write-Host "WARNING: LICENSE.txt not found, creating default..." -ForegroundColor Yellow
    
    $licenseContent = "OPSIS Agent - License Agreement`r`n`r`n"
    $licenseContent += "Copyright (c) 2024 OPSIS`r`n`r`n"
    $licenseContent += "This software is proprietary and confidential.`r`n"
    $licenseContent += "Unauthorized copying or distribution is prohibited.`r`n`r`n"
    $licenseContent += "For licensing inquiries: contact@opsis.io`r`n"
    
    Set-Content -Path "LICENSE.txt" -Value $licenseContent
    Write-Host "  + Created default LICENSE.txt" -ForegroundColor Green
}

Write-Host ""
Write-Host "Building application..." -ForegroundColor Yellow

# Build the application (TypeScript + GUI)
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  + TypeScript build complete" -ForegroundColor Green

# Build standalone service executable
Write-Host "Building standalone service executable..." -ForegroundColor Yellow
npm run build:exe
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Executable build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  + Standalone exe build complete" -ForegroundColor Green

Write-Host ""
Write-Host "Compiling installer..." -ForegroundColor Yellow

# Create output directory
New-Item -ItemType Directory -Force -Path "installer-output" | Out-Null

# Compile installer
& $innoPath "installer.iss"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SUCCESS! Installer created" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    $installerPath = Get-ChildItem "installer-output\OPSIS-Agent-Setup-*.exe" | Select-Object -First 1
    
    if ($installerPath) {
        $size = [math]::Round($installerPath.Length / 1MB, 2)
        Write-Host "Location: $($installerPath.FullName)" -ForegroundColor Cyan
        Write-Host "Size: $size MB" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Test on clean VM" -ForegroundColor White
        Write-Host "  2. Code sign (optional): signtool sign ..." -ForegroundColor White
        Write-Host "  3. Deploy to test machines" -ForegroundColor White
        Write-Host ""
        Write-Host "Silent install: $($installerPath.Name) /VERYSILENT /NORESTART" -ForegroundColor Gray
        Write-Host ""
    }
} else {
    Write-Host ""
    Write-Host "ERROR: Installer compilation failed!" -ForegroundColor Red
    Write-Host "Check the error messages above" -ForegroundColor Yellow
    exit 1
}
