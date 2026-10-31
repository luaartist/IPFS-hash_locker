<#
.SYNOPSIS
    Locks and encrypts a file or directory into an HLK / Encrypted Bundle on Windows.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Inputs,
    [Parameter(Mandatory=$true)]
    [string]$OutputFile,
    [string]$Passphrase,
    [string]$SignKey,
    [string]$PythonExe = "python"
)

$argsList = @("-m", "ipfs_locker.cli", "hlk-lock")
foreach ($inp in $Inputs) { $argsList += $inp }
$argsList += @("-o", $OutputFile)

if ($Passphrase) {
    $argsList += @("-k", $Passphrase)
}
if ($SignKey) {
    $argsList += @("--sign-key", $SignKey)
}

Write-Host "[*] Creating secure HLK container: $OutputFile" -ForegroundColor Cyan
& $PythonExe $argsList
