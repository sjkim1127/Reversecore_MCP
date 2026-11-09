# ==============================================================================
# Reversecore_MCP One-line Installer & Setup Wizard (Windows PowerShell)
#
# Usage:
#   irm https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.ps1 | iex
#   .\install.ps1 [options]
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$All,
    [string]$Clients,
    [string]$Mode = "auto",
    [switch]$Docker,
    [switch]$Uvx,
    [switch]$Pipx,
    [string]$Command,
    [string[]]$Args,
    [switch]$DryRun,
    [switch]$Remove,
    [switch]$List,
    [switch]$Tiered
)

$ErrorActionPreference = "Stop"

function Find-Python {
    $candidates = @("python", "py -3.12", "py -3.11", "py -3.10", "py")
    foreach ($cmd in $candidates) {
        try {
            $parts = $cmd.Split(" ")
            $exe = $parts[0]
            $cmdArgs = @()
            if ($parts.Length -gt 1) {
                $cmdArgs = $parts[1..($parts.Length - 1)]
            }
            $testArgs = $cmdArgs + @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            $ver = & $exe $testArgs 2>$null
            if ($ver -and [version]$ver -ge [version]"3.10") {
                return $cmd
            }
        } catch {}
    }
    return $null
}

# Pass-through arguments to python setup script
$passArgs = @($args)
if ($All) { $passArgs += "--all" }
if ($Clients) { $passArgs += @("--clients", $Clients) }
if ($Docker) { $passArgs += "--docker" }
if ($Uvx) { $passArgs += "--uvx" }
if ($Pipx) { $passArgs += "--pipx" }
if ($Command) { $passArgs += @("--command", $Command) }
if ($DryRun) { $passArgs += "--dry-run" }
if ($Remove) { $passArgs += "--remove" }
if ($List) { $passArgs += "--list" }
if ($Tiered) { $passArgs += "--tiered" }

# If inside local repository clone
if (Test-Path "reversecore_mcp\setup.py") {
    if (Test-Path "venv\Scripts\python.exe") {
        & "venv\Scripts\python.exe" -m reversecore_mcp.setup @passArgs
        exit $LASTEXITCODE
    }
    $py = Find-Python
    if ($py) {
        $parts = $py.Split(" ")
        $exe = $parts[0]
        $cmdArgs = @()
        if ($parts.Length -gt 1) {
            $cmdArgs = $parts[1..($parts.Length - 1)]
        }
        & $exe ($cmdArgs + @("-m", "reversecore_mcp.setup") + $passArgs)
        exit $LASTEXITCODE
    }
}

# If reversecore-mcp is in PATH
if (Get-Command "reversecore-mcp" -ErrorAction SilentlyContinue) {
    & reversecore-mcp setup @passArgs
    exit $LASTEXITCODE
}

# If uvx is available
if (Get-Command "uvx" -ErrorAction SilentlyContinue) {
    Write-Host "🚀 Running Reversecore setup via uvx..." -ForegroundColor Cyan
    & uvx --from reversecore-mcp reversecore-setup @passArgs
    exit $LASTEXITCODE
}

# If pipx is available
if (Get-Command "pipx" -ErrorAction SilentlyContinue) {
    Write-Host "🚀 Running Reversecore setup via pipx..." -ForegroundColor Cyan
    & pipx run reversecore-mcp setup @passArgs
    exit $LASTEXITCODE
}

# Fallback: install in isolated virtualenv
$py = Find-Python
if ($py) {
    $installDir = Join-Path $env:USERPROFILE ".reversecore-mcp"
    $venvDir = Join-Path $installDir "venv"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"

    Write-Host "📦 Installing Reversecore_MCP into isolated environment: $venvDir" -ForegroundColor Cyan
    if (-not (Test-Path $venvDir)) {
        $parts = $py.Split(" ")
        $exe = $parts[0]
        $cmdArgs = @()
        if ($parts.Length -gt 1) {
            $cmdArgs = $parts[1..($parts.Length - 1)]
        }
        & $exe ($cmdArgs + @("-m", "venv", $venvDir))
    }

    Write-Host "⬇️  Fetching reversecore-mcp package..." -ForegroundColor Cyan
    & $venvPython -m pip install --upgrade --quiet pip reversecore-mcp
    & $venvPython -m reversecore_mcp.setup @passArgs
    exit $LASTEXITCODE
}

Write-Error "Python 3.10+ or uv / pipx is required to install Reversecore_MCP."
exit 1
