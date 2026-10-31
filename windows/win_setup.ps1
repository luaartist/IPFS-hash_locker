<#
.SYNOPSIS
    Bootstraps the IPFS Hash Locker environment on Windows.
.DESCRIPTION
    Installs Python dependencies, verifies IPFS Kubo installation, and validates cryptographic libraries.
#>

[CmdletBinding()]
param(
    [string]$PythonExe = "python"
)

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   IPFS Hash Locker - Windows Environment Setup" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1. Check Python version
try {
    $pyVer = & $PythonExe --version 2>&1
    Write-Host "[+] Found Python: $pyVer" -ForegroundColor Green
} catch {
    Write-Error "[-] Python not found. Please specify -PythonExe with the full path to python.exe"
    exit 1
}

# 2. Install dependencies with trusted hosts
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
& $PythonExe -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org -r ..equirements.txt cryptography argon2-cffi cbor2 zstandard blake3 pymupdf respx pytest

# 3. Check IPFS Kubo CLI
try {
    $ipfsVer = ipfs version 2>&1
    Write-Host "[+] Local IPFS Kubo available: $ipfsVer" -ForegroundColor Green
} catch {
    Write-Warning "[!] IPFS Kubo CLI not detected in PATH. Local daemon features will use gateway mode."
}

Write-Host "[+] Setup complete! You can now run tests with: & '$PythonExe' -m pytest ..	ests -v" -ForegroundColor Green
