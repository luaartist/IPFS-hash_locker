# Windows Platform Integration Guide

This directory contains native PowerShell automation and platform adapters for running **IPFS Hash Locker** on Windows systems.

---

## Quickstart (Windows PowerShell)

### 1. Environment Setup
```powershell
.\win_setup.ps1
```

### 2. Lock & Encrypt Files into HLK v2 Container
```powershell
.\win_lock.ps1 -Inputs "document.pdf" -OutputFile "bundle.hlk" -Passphrase "MySecretPassword123"
```

### 3. Unlock & Forensically Verify Container
```powershell
.\win_unlock.ps1 -ContainerPath "bundle.hlk" -OutputDirectory ".\extracted_files" -Passphrase "MySecretPassword123"
```

### 4. Zero-Copy Tensor Checkpoint Verification
```powershell
.\win_verify.ps1 -TargetFile "model.safetensors" -Tensor
```
