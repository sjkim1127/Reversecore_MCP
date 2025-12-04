# =============================================================================
# Ghidra Installation Script for Windows
# =============================================================================
# This script downloads and installs Ghidra to the Reversecore MCP Tools directory
# Usage: .\scripts\install-ghidra.ps1 [-Version "11.4.3"] [-InstallDir ".\Tools"]
#
# Default installation: <project_root>\Tools\ghidra_<version>

param(
    [string]$Version = "11.4.3",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

# Get script directory and project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Default to project Tools directory if not specified
if ([string]::IsNullOrEmpty($InstallDir)) {
    $InstallDir = Join-Path $ProjectRoot "Tools"
}

# Ghidra release URL pattern
$GhidraReleasesApi = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_${Version}_build"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Ghidra $Version Installation Script" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Project Root: $ProjectRoot" -ForegroundColor Gray
Write-Host "Install Dir:  $InstallDir" -ForegroundColor Gray
Write-Host ""

# Step 1: Create Tools directory
Write-Host "[1/5] Creating installation directory..." -ForegroundColor Yellow
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "  Created: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "  Already exists: $InstallDir" -ForegroundColor Green
}

# Step 2: Get download URL from GitHub API
Write-Host "[2/5] Fetching release information from GitHub..." -ForegroundColor Yellow
try {
    $headers = @{
        "Accept" = "application/vnd.github.v3+json"
        "User-Agent" = "Reversecore-MCP-Installer"
    }
    $release = Invoke-RestMethod -Uri $GhidraReleasesApi -Headers $headers
    
    # Find the zip asset
    $zipAsset = $release.assets | Where-Object { $_.name -like "ghidra_*.zip" } | Select-Object -First 1
    
    if (!$zipAsset) {
        throw "Could not find Ghidra zip file in release assets"
    }
    
    $downloadUrl = $zipAsset.browser_download_url
    $fileName = $zipAsset.name
    Write-Host "  Found: $fileName" -ForegroundColor Green
} catch {
    Write-Host "  Error fetching release info: $_" -ForegroundColor Red
    Write-Host "  Trying direct URL pattern..." -ForegroundColor Yellow
    
    # Fallback: Try common date patterns (Ghidra releases usually on specific dates)
    $today = Get-Date
    $possibleDates = @(
        $today.ToString("yyyyMMdd"),
        $today.AddDays(-1).ToString("yyyyMMdd"),
        $today.AddDays(-2).ToString("yyyyMMdd"),
        "20251204",  # Known release date for 11.4.3
        "20251203"
    )
    
    $downloadUrl = $null
    foreach ($date in $possibleDates) {
        $testUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${Version}_build/ghidra_${Version}_PUBLIC_$date.zip"
        try {
            $null = Invoke-WebRequest -Uri $testUrl -Method Head -UseBasicParsing -ErrorAction Stop
            $downloadUrl = $testUrl
            $fileName = "ghidra_${Version}_PUBLIC_$date.zip"
            Write-Host "  Found: $fileName" -ForegroundColor Green
            break
        } catch {
            continue
        }
    }
    
    if (!$downloadUrl) {
        Write-Host ""
        Write-Host "ERROR: Could not find Ghidra download URL automatically." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please download manually from:" -ForegroundColor Yellow
        Write-Host "  https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_${Version}_build" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Then extract to: $InstallDir" -ForegroundColor Yellow
        exit 1
    }
}

# Step 3: Download Ghidra
$downloadPath = Join-Path $env:TEMP $fileName
Write-Host "[3/5] Downloading Ghidra ($fileName)..." -ForegroundColor Yellow
Write-Host "  URL: $downloadUrl" -ForegroundColor Gray
Write-Host "  This may take several minutes (~400MB)..." -ForegroundColor Gray

try {
    # Use BITS for faster download with progress
    $bitsSupported = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
    
    if ($bitsSupported) {
        Start-BitsTransfer -Source $downloadUrl -Destination $downloadPath -Description "Downloading Ghidra $Version"
    } else {
        # Fallback to Invoke-WebRequest with progress
        $ProgressPreference = 'Continue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing
    }
    
    $fileSize = (Get-Item $downloadPath).Length / 1MB
    Write-Host "  Downloaded: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Green
} catch {
    Write-Host "  Download failed: $_" -ForegroundColor Red
    exit 1
}

# Step 4: Extract Ghidra
Write-Host "[4/5] Extracting Ghidra to $InstallDir..." -ForegroundColor Yellow
Write-Host "  This may take a minute..." -ForegroundColor Gray

try {
    # Extract using Expand-Archive
    Expand-Archive -Path $downloadPath -DestinationPath $InstallDir -Force
    
    # Find the extracted directory name
    $extractedDir = Get-ChildItem -Path $InstallDir -Directory | Where-Object { $_.Name -like "ghidra_*" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    if ($extractedDir) {
        $ghidraPath = $extractedDir.FullName
        Write-Host "  Extracted to: $ghidraPath" -ForegroundColor Green
    } else {
        throw "Could not find extracted Ghidra directory"
    }
} catch {
    Write-Host "  Extraction failed: $_" -ForegroundColor Red
    exit 1
}

# Step 5: Set environment variable
Write-Host "[5/5] Setting environment variable..." -ForegroundColor Yellow

# Set for current session
$env:GHIDRA_INSTALL_DIR = $ghidraPath

# Set permanently for user
[Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", $ghidraPath, "User")
Write-Host "  GHIDRA_INSTALL_DIR = $ghidraPath" -ForegroundColor Green

# Create .env file in project root if it doesn't have GHIDRA_INSTALL_DIR
$envFile = Join-Path $ProjectRoot ".env"
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile -Raw
    if ($envContent -notmatch "GHIDRA_INSTALL_DIR") {
        Add-Content -Path $envFile -Value "`nGHIDRA_INSTALL_DIR=$ghidraPath"
        Write-Host "  Added to .env file" -ForegroundColor Green
    }
} else {
    # Create .env with Ghidra path
    "GHIDRA_INSTALL_DIR=$ghidraPath" | Out-File -FilePath $envFile -Encoding utf8
    Write-Host "  Created .env file" -ForegroundColor Green
}

# Cleanup
Write-Host ""
Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Ghidra installed to: $ghidraPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Environment variable set:" -ForegroundColor Yellow
Write-Host "  GHIDRA_INSTALL_DIR = $ghidraPath" -ForegroundColor White
Write-Host ""
Write-Host "To use in current terminal, restart PowerShell or run:" -ForegroundColor Yellow
Write-Host "  `$env:GHIDRA_INSTALL_DIR = '$ghidraPath'" -ForegroundColor White
Write-Host ""
Write-Host "To launch Ghidra GUI:" -ForegroundColor Yellow
Write-Host "  & '$ghidraPath\ghidraRun.bat'" -ForegroundColor White
Write-Host ""

# Check for Java
Write-Host "Checking Java installation..." -ForegroundColor Yellow
$javaVersion = & java -version 2>&1 | Select-Object -First 1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Java found: $javaVersion" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Java not found!" -ForegroundColor Red
    Write-Host "  Ghidra requires JDK 17 or later." -ForegroundColor Yellow
    Write-Host "  Download from: https://adoptium.net/" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
