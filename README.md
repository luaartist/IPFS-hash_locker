# 🔐 IPFS Hash Locker

**Sovereign cryptographic container, forensic integrity validator, and decentralized IPFS/Filecoin ledger.**

[![Tests](https://img.shields.io/badge/tests-32%20passed-brightgreen.svg)](tests/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20(Ubuntu)-lightgrey.svg)](windows/)
[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa.svg?logo=github)](https://github.com/sponsors/luaartist)
[![Patreon](https://img.shields.io/badge/Patreon-AIIQ-FF424D.svg?logo=patreon)](https://www.patreon.com/cw/AIIQ)

---

## 🌟 Key Capabilities

* **HLK v2 Wire Protocol**: Deterministic binary header (`b"HLKv2\x00\x00\x00"`), canonical CBOR metadata, Compress-then-Encrypt (Zstandard Level 19) pipeline, AES-256-GCM-SIV / ChaCha20-Poly1305 AEAD, Argon2id memory-hard key derivation, and detached Ed25519 digital signatures.
* **Reserved v2 Wire Header Extension / Roadmap Specification**: Header slot reserved for post-quantum hybrid attestations (including ML-DSA / FIPS 204 parameter sets) for forward-compatible verification.
* **Dual-Layer Forensic PDF Engine**: Canonical COS object graph digest (BLAKE3) combined with deterministic 300 DPI grayscale rasterization and normalized text run digests.
* **Zero-Copy Tensor Hashing (`Blake3MmapHasher`)**: Multi-core memory-mapped zero-copy slicing for multi-gigabyte neural checkpoints (SafeTensors) without Python GIL bottlenecks.
* **Cryptographic Provenance & Merkle Roots**: 256-bit cryptographic Merkle tree anchors and OpenTimestamps-compatible Bitcoin block header commitment packets.
* **Pluggable Storage Backends**: Dynamic registry supporting LocalFS, Kubo IPFS RPC, CAR v1 streaming, and Filecoin integration.
* **Multi-Platform Native Support**: Dedicated Windows PowerShell adapters (`windows/`) alongside Linux/Ubuntu scripts and CLI.

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.10 or higher
* (Optional) IPFS Kubo Node 0.20+

### Windows Setup
```powershell
cd windows
.\win_setup.ps1
```

### Linux / Ubuntu Setup
```bash
pip install -e .
```

---

## 💻 Command Line Interface (CLI)

```bash
# 1. Lock and encrypt into HLK v2 container
ipfs-locker hlk-lock doc.pdf -o output.hlk -k "Passphrase123"

# 2. Verify and unlock HLK v2 container
ipfs-locker hlk-unlock output.hlk -o ./extracted -k "Passphrase123"

# 3. Verify multi-gigabyte neural tensor checkpoint
ipfs-locker tensor-verify /path/to/model.safetensors

# 4. Extract PDF dual-layer forensic hashes
ipfs-locker pdf-info document.pdf

# 5. Generate Merkle Tree timestamp anchor
ipfs-locker anchor file1.txt file2.pdf
```

---

## 🧪 Automated Test Suite

```bash
pytest -v
```

All 32 test cases across cryptographic engines, HLK v2 containers, PDF forensics, and storage backends run deterministically across both Windows and Linux.

---

## 💖 Support & Funding

If you find this sovereign cryptographic infrastructure valuable, consider supporting continued research and development:

* **GitHub Sponsors**: [github.com/sponsors/luaartist](https://github.com/sponsors/luaartist)
* **Patreon**: [patreon.com/cw/AIIQ](https://www.patreon.com/cw/AIIQ)

---

## ⚖️ Regulatory Notice & Export Administration Compliance

This repository contains publicly available source code using standard cryptography and is not subject to the Export Administration Regulations (EAR) pursuant to 15 CFR § 734.3(b)(3), § 734.7, and § 742.15(b)(1).

---

## 📄 License & Commercial Dual-Licensing

This repository is licensed under the **GNU Affero General Public License v3.0** (GNU AGPLv3) for open-source use. See [LICENSE](LICENSE) for terms.

*Commercial and proprietary enterprise licenses are available for commercial production, closed-source distribution, or customized embedded deployments. Contact the author for commercial licensing inquiries.*
