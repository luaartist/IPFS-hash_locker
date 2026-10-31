<#
.SYNOPSIS
    Verifies the integrity of a file, tensor checkpoint, or HLK container on Windows.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFile,
    [switch]$Tensor,
    [string]$PythonExe = "python"
)

if ($Tensor) {
    Write-Host "[*] Verifying multi-gigabyte neural tensor checkpoint: $TargetFile" -ForegroundColor Cyan
    & $PythonExe -m ipfs_locker.cli tensor-verify $TargetFile
} else {
    Write-Host "[*] Verifying file hash / companion metadata: $TargetFile" -ForegroundColor Cyan
    & $PythonExe -m ipfs_locker.cli verify $TargetFile
}
