#!/usr/bin/env pwsh
# Build script for CVM Attestation Tools
# Can be run locally or from GitHub Actions
param(
    [switch]$SkipInstall,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n$Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Yellow
}

try {
    Write-Host "=== CVM Attestation Tools - Build Script ===" -ForegroundColor Cyan
    Write-Info "Working directory: $(Get-Location)"

    # Step 1: Install dependencies (unless skipped)
    if (-not $SkipInstall) {
        Write-Step "[1/6] Installing dependencies..."
        if (Test-Path ".\install.ps1") {
            .\install.ps1
            Write-Success "Dependencies installed"
        } else {
            Write-Host "Warning: install.ps1 not found, skipping dependency installation" -ForegroundColor Yellow
        }
    } else {
        Write-Info "[1/6] Skipping dependency installation (--SkipInstall flag set)"
    }

    # Step 2: Install PyInstaller
    Write-Step "[2/6] Installing PyInstaller..."
    python.exe -m pip install pyinstaller --quiet --disable-pip-version-check
    Write-Success "PyInstaller installed"

    # Step 3: Build attest
    Write-Step "[3/6] Building attest..."
    python.exe -m PyInstaller --onefile --distpath dist --clean .\attest.py
    if ($LASTEXITCODE -ne 0) { 
        throw "Failed to build attest"
    }
    Write-Success "attest built successfully"

    # Step 4: Build read_report
    Write-Step "[4/6] Building read_report..."
    python.exe -m PyInstaller --onefile --distpath dist --clean .\read_report.py
    if ($LASTEXITCODE -ne 0) { 
        throw "Failed to build read_report"
    }
    Write-Success "read_report built successfully"

    # Step 5: Copy configuration files
    Write-Step "[5/6] Copying configuration files..."
    Copy-Item *.json dist\ -ErrorAction Stop
    Write-Success "Configuration files copied"

    # Step 6: Verify and prepare release
    Write-Step "[6/6] Verifying and preparing release..."
    
    # Verify executables exist
    $attest = if ($IsWindows -or $env:OS -match "Windows") { "dist\attest.exe" } else { "dist/attest" }
    $readReport = if ($IsWindows -or $env:OS -match "Windows") { "dist\read_report.exe" } else { "dist/read_report" }
    
    if (-not (Test-Path $attest)) {
        throw "Executable not found: $attest"
    }
    if (-not (Test-Path $readReport)) {
        throw "Executable not found: $readReport"
    }
    
    Write-Success "Both executables verified"

    # Show dist contents
    if ($Verbose) {
        Write-Info "Contents of dist directory:"
        Get-ChildItem dist | Format-Table Name, Length
    }

    # Prepare clean release directory
    if (Test-Path "release") {
        Remove-Item -Recurse -Force release
    }
    New-Item -ItemType Directory -Force -Path release | Out-Null
    
    Copy-Item $attest release\
    Copy-Item $readReport release\
    Copy-Item *.json release\
    
    Write-Success "Release directory prepared"
    
    # Show release contents
    Write-Info "Release directory contents:"
    Get-ChildItem release | Format-Table Name, Length

    $releaseSize = (Get-ChildItem release -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    Write-Host "`n✅ BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "Release package size: $($releaseSize.ToString('F2')) MB" -ForegroundColor Cyan
    Write-Host "Artifacts available in: $(Join-Path (Get-Location) 'release')" -ForegroundColor Yellow
    
    exit 0
}
catch {
    Write-Host "`n❌ BUILD FAILED: $_" -ForegroundColor Red
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "- Ensure Python is installed and in PATH" -ForegroundColor Yellow
    Write-Host "- Run without --SkipInstall to install dependencies" -ForegroundColor Yellow
    Write-Host "- Check that all required modules are available" -ForegroundColor Yellow
    exit 1
}
