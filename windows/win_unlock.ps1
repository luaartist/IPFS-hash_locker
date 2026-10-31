<#
.SYNOPSIS
    Unlocks and verifies an HLK / Encrypted Bundle on Windows.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ContainerPath,
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory,
    [string]$Passphrase,
    [string]$PublicKey,
    [string]$PythonExe = "python"
)

$argsList = @("-m", "ipfs_locker.cli", "hlk-unlock", $ContainerPath, "-o", $OutputDirectory)

if ($Passphrase) {
    $argsList += @("-k", $Passphrase)
}
if ($PublicKey) {
    $argsList += @("--public-key", $PublicKey)
}

Write-Host "[*] Unlocking and verifying container: $ContainerPath" -ForegroundColor Cyan
& $PythonExe $argsList
