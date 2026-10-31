# PowerShell script to verify file integrity against companion or inline ##hash metadata.

param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    [switch]$InternalHash
)

if (-not (Test-Path -Path $FilePath)) {
    Write-Host "File not found: $FilePath" -ForegroundColor Red
    exit 1
}

$currentHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash

if ($InternalHash) {
    $content = Get-Content -Path $FilePath -Raw
    if ($content -match '##hash ([0-9a-fA-F]{64})') {
        $storedHash = $matches[1]
        $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
        $pattern = switch ($ext) {
            ".ps1" { "
# ##hash [0-9a-fA-F]{64}" }
            ".py"  { "
# ##hash [0-9a-fA-F]{64}" }
            ".lua" { "
-- ##hash [0-9a-fA-F]{64}" }
            default { "
##hash [0-9a-fA-F]{64}" }
        }
        $cleaned = $content -replace $pattern, ""
        $computed = (Get-FileHash -InputObject $cleaned -Algorithm SHA256).Hash
        if ($storedHash -eq $computed) {
            Write-Host "PASS: Inline hash verified for $FilePath ($computed)" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "FAIL: Hash mismatch for $FilePath! Stored: $storedHash, Computed: $computed" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "No inline ##hash found in $FilePath" -ForegroundColor Yellow
        exit 1
    }
} else {
    $hashFile = "$FilePath.hash"
    if (Test-Path -Path $hashFile) {
        $content = Get-Content -Path $hashFile -Raw
        if ($content -match '##hash ([0-9a-fA-F]{64})') {
            $storedHash = $matches[1]
            if ($storedHash -eq $currentHash) {
                Write-Host "PASS: Companion hash verified for $FilePath ($currentHash)" -ForegroundColor Green
                exit 0
            } else {
                Write-Host "FAIL: Hash mismatch! Stored: $storedHash, Current: $currentHash" -ForegroundColor Red
                exit 1
            }
        }
    } else {
        Write-Host "No companion file found: $hashFile" -ForegroundColor Yellow
        exit 1
    }
}
