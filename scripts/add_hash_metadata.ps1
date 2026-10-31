# PowerShell script to add hash metadata to project files
# Computes SHA-256 hashes for specified files and adds them as metadata
# either as an inline ##hash comment or as a companion .hash file.

param (
    [string[]]$Files,
    [switch]$InternalHash
)

if (-not $Files -or $Files.Count -eq 0) {
    Write-Host "Usage: .\add_hash_metadata.ps1 -Files file1.py,file2.ps1 [-InternalHash]" -ForegroundColor Yellow
    exit 0
}

function Add-HashMetadata {
    param (
        [string]$filePath,
        [switch]$internal
    )
    if (-not (Test-Path -Path $filePath)) {
        Write-Host "File not found: $filePath" -ForegroundColor Red
        return $false
    }
    try {
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        if ($internal) {
            $fileContent = Get-Content -Path $filePath -Raw
            if ($fileContent -match '##hash [0-9a-fA-F]{64}') {
                Write-Host "File already has an inline hash: $filePath" -ForegroundColor Yellow
                return $false
            }
            $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
            $hashLine = switch ($ext) {
                ".ps1" { "`n# ##hash $hash" }
                ".py"  { "`n# ##hash $hash" }
                ".lua" { "`n-- ##hash $hash" }
                ".js"  { "`n// ##hash $hash" }
                default { "`n##hash $hash" }
            }
            Add-Content -Path $filePath -Value $hashLine
            Write-Host "Added inline hash to: $filePath" -ForegroundColor Green
        }
        else {
            $hashFilePath = "$filePath.hash"
            Set-Content -Path $hashFilePath -Value "##hash $hash"
            Write-Host "Created companion hash file: $hashFilePath" -ForegroundColor Green
        }
        return $true
    }
    catch {
        Write-Host "Error adding hash to $filePath`: $_" -ForegroundColor Red
        return $false
    }
}

foreach ($f in $Files) {
    Add-HashMetadata -filePath $f -internal:$InternalHash
}
