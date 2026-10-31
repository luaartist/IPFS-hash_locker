"""
Unified Command-Line Interface for IPFS Hash Locker.
Upgraded with HLK v2 container operations, zero-copy SafeTensor hashing,
OpenTimestamps commitments, and DAG-CBOR/CAR streaming.
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from .crypto import encrypt_file, decrypt_file, package_and_encrypt_bundle, unpack_and_decrypt_bundle
from .hasher import (
    compute_file_hash,
    create_hash_companion,
    verify_hash_companion,
    embed_hash_in_file,
    verify_file_hash,
    Blake3MmapHasher,
)
from .ipfs_client import IPFSClient
from .provenance import ProvenanceEngine, MerkleTree, OTSCommitment
from .pdf_processor import PDFProcessor
from .hlk import HLKContainer


def main():
    parser = argparse.ArgumentParser(
        prog="ipfs-locker",
        description="IPFS Hash Locker: Encrypt, Package HLK v2, Upload to IPFS, and Audit Document Provenance.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Lock (Legacy & Standard Zip Bundle)
    p_lock = subparsers.add_parser("lock", help="Encrypt and bundle files with SHA-256 manifest.")
    p_lock.add_argument("files", nargs="+", help="Files to package and encrypt.")
    p_lock.add_argument("-o", "--output", required=True, help="Output encrypted archive path (.zip.enc).")
    p_lock.add_argument("-k", "--key", required=True, help="Encryption passphrase or 32-byte hex key.")
    p_lock.add_argument("--cipher", default="aes-gcm-siv", choices=["aes-gcm", "aes-gcm-siv", "chacha20-poly1305"], help="AEAD cipher.")

    # 2. Unlock (Decrypt & Unpack)
    p_unlock = subparsers.add_parser("unlock", help="Decrypt and extract an encrypted bundle, verifying hashes.")
    p_unlock.add_argument("archive", help="Encrypted archive path (.zip.enc).")
    p_unlock.add_argument("-o", "--output-dir", required=True, help="Directory to extract files into.")
    p_unlock.add_argument("-k", "--key", required=True, help="Decryption passphrase or key.")

    # 3. HLK Lock (HLK v2 Container)
    p_hlk_lock = subparsers.add_parser("hlk-lock", help="Package file into an authenticated, Zstd-compressed HLK v2 container.")
    p_hlk_lock.add_argument("file", help="Source file or PDF to lock.")
    p_hlk_lock.add_argument("-o", "--output", required=True, help="Output .hlk file path.")
    p_hlk_lock.add_argument("-k", "--key", required=True, help="Passphrase or key.")
    p_hlk_lock.add_argument("--cipher", default="aes-gcm-siv", choices=["aes-gcm-siv", "chacha20-poly1305", "aes-gcm"], help="AEAD cipher.")
    p_hlk_lock.add_argument("--sign-key", help="Path to Ed25519 private key file or 32-byte raw/hex signing key.")

    # 4. HLK Unlock
    p_hlk_unlock = subparsers.add_parser("hlk-unlock", help="Unpack and decrypt an HLK v2 container.")
    p_hlk_unlock.add_argument("hlk_file", help="Target .hlk container.")
    p_hlk_unlock.add_argument("-o", "--output", required=True, help="Output file path.")
    p_hlk_unlock.add_argument("-k", "--key", required=True, help="Passphrase or key.")

    # 5. HLK Verify (Public verification)
    p_hlk_verify = subparsers.add_parser("hlk-verify", help="Inspect and publicly verify an HLK container manifest and signatures.")
    p_hlk_verify.add_argument("hlk_file", help="Target .hlk container.")

    # 6. Tensor Zero-Copy Hashing
    p_tensor = subparsers.add_parser("tensor-verify", help="Run multi-core zero-copy BLAKE3 hashing over large SafeTensors.")
    p_tensor.add_argument("file", help="Path to SafeTensors or neural model file.")
    p_tensor.add_argument("--workers", type=int, default=None, help="Parallel worker thread count.")

    # 7. Upload to IPFS
    p_upload = subparsers.add_parser("upload", help="Upload a file or encrypted bundle to IPFS.")
    p_upload.add_argument("file", help="File to upload.")
    p_upload.add_argument("--rpc", default="http://127.0.0.1:5001", help="IPFS RPC endpoint.")

    # 8. Download from IPFS
    p_download = subparsers.add_parser("download", help="Download content by CID from IPFS.")
    p_download.add_argument("cid", help="IPFS Content Identifier (CID).")
    p_download.add_argument("-o", "--output", required=True, help="Output file path.")
    p_download.add_argument("--rpc", default="http://127.0.0.1:5001", help="IPFS RPC endpoint.")
    p_download.add_argument("--gateway", default="https://ipfs.io/ipfs", help="IPFS gateway fallback.")

    # 9. Verify Hash
    p_verify = subparsers.add_parser("verify", help="Verify the SHA-256 / BLAKE2b / BLAKE3 hash or companion of a file.")
    p_verify.add_argument("file", help="File to verify.")
    p_verify.add_argument("--algo", default="sha256", choices=["sha256", "blake2b", "blake3"], help="Hash algorithm.")
    p_verify.add_argument("--expected", help="Expected hash hex to compare against.")

    # 10. PDF Inspect
    p_pdf = subparsers.add_parser("pdf-info", help="Extract PDF structural and perceptual digests.")
    p_pdf.add_argument("pdf", help="Path to PDF file.")

    # 11. Anchor (Provenance & OTS)
    p_anchor = subparsers.add_parser("anchor", help="Generate a cryptographic 256-bit Merkle & OTS anchor for a document.")
    p_anchor.add_argument("file", help="File to anchor.")

    args = parser.parse_args()

    if args.command == "lock":
        out_path, meta = package_and_encrypt_bundle(args.files, args.output, args.key, cipher=args.cipher)
        print(f"[+] Encrypted bundle created: {out_path}")
        print(f"[+] Manifest file hashes: {json.dumps(meta.get('file_hashes'), indent=2)}")

    elif args.command == "unlock":
        manifest = unpack_and_decrypt_bundle(args.archive, args.output_dir, args.key)
        print(f"[+] Bundle decrypted into: {args.output_dir}")
        file_hashes = manifest.get("file_hashes", {})
        all_valid = True
        for name, expected_hash in file_hashes.items():
            extracted_file = Path(args.output_dir) / name
            if extracted_file.exists():
                computed = compute_file_hash(extracted_file)
                match = computed == expected_hash
                status = "[OK]" if match else "[FAILED]"
                print(f"  {status} {name}: {computed}")
                if not match:
                    all_valid = False
            else:
                print(f"  [MISSING] {name}")
                all_valid = False
        print(f"[+] Integrity check: {'PASSED' if all_valid else 'FAILED'}")

    elif args.command == "hlk-lock":
        p = Path(args.file)
        payload = p.read_bytes()
        is_pdf = p.suffix.lower() == ".pdf"
        signing_key = None
        if args.sign_key:
            sk_path = Path(args.sign_key)
            if sk_path.exists():
                raw_sk = sk_path.read_bytes()
                if len(raw_sk) == 32:
                    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_sk)
                elif len(raw_sk) == 64:
                    # Hex-encoded string
                    try:
                        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_sk.decode("utf-8").strip()))
                    except Exception:
                        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_sk[:32])
                else:
                    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_sk[:32])
            else:
                try:
                    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.sign_key))
                except Exception:
                    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(args.sign_key.encode("utf-8")[:32].ljust(32, b"\x00"))

        hlk_bytes = HLKContainer.create_package(
            payload,
            args.key,
            signing_key=signing_key,
            cipher=args.cipher,
            is_pdf=is_pdf,
            pdf_path=p if is_pdf else None,
        )
        Path(args.output).write_bytes(hlk_bytes)
        print(f"[+] HLK v2 container created: {args.output} ({len(hlk_bytes)} bytes)")

    elif args.command == "hlk-unlock":
        hlk_bytes = Path(args.hlk_file).read_bytes()
        payload, manifest = HLKContainer.unpack_package(hlk_bytes, args.key)
        Path(args.output).write_bytes(payload)
        print(f"[+] Unpacked and verified HLK payload to: {args.output}")

    elif args.command == "hlk-verify":
        hlk_bytes = Path(args.hlk_file).read_bytes()
        manifest = HLKContainer.read_manifest(hlk_bytes)
        print(f"[+] HLK Manifest ({manifest.get('schema', 'unknown')}):")
        print(f"    Schema: {manifest.get('schema')}")
        print(f"    Cipher: {manifest.get('cipher')}")
        print(f"    CT BLAKE3: {manifest.get('ct_blake3', b'').hex()}")
        print(f"    Timestamp: {manifest.get('created_at', manifest.get('timestamp_utc'))}")
        if manifest.get("signature_algorithm") != "none":
            valid_sig = HLKContainer.verify_public_signature(hlk_bytes)
            print(f"    Signature: {manifest.get('signature_algorithm')} ({'[VALID]' if valid_sig else '[INVALID]'})")

    elif args.command == "tensor-verify":
        hasher = Blake3MmapHasher(max_workers=args.workers)
        res = hasher.hash_file(args.file)
        print(f"[+] Tensor Hashing Completed:")
        print(f"    File: {args.file}")
        print(f"    Size: {res.size_bytes} bytes")
        print(f"    BLAKE3: {res.blake3_hex}")
        print(f"    SHA-256: {res.sha256_hex}")
        print(f"    Predicted CID: {res.cid}")

    elif args.command == "upload":
        client = IPFSClient(rpc_url=args.rpc)
        res = client.upload_file(args.file)
        print(f"[+] Uploaded to IPFS successfully!")
        print(f"    CID: {res.get('Hash')}")
        print(f"    Size: {res.get('Size')} bytes")

    elif args.command == "download":
        client = IPFSClient(rpc_url=args.rpc, gateway_url=args.gateway)
        p = client.download_file(args.cid, args.output)
        h = compute_file_hash(p)
        print(f"[+] Downloaded CID {args.cid} -> {p}")
        print(f"[+] Recovered SHA-256: {h}")

    elif args.command == "verify":
        p = Path(args.file)
        computed = compute_file_hash(p, algorithm=args.algo)
        print(f"Computed {args.algo.upper()}: {computed}")
        if args.expected:
            if computed.lower() == args.expected.lower():
                print("[+] VERIFIED: Hash matches expected value.")
            else:
                print("[-] FAILED: Hash does not match expected value.")
                sys.exit(1)

    elif args.command == "pdf-info":
        info = PDFProcessor.get_pdf_info(args.pdf)
        print(json.dumps(info, indent=2))

    elif args.command == "anchor":
        anchor = ProvenanceEngine.generate_anchor(args.file)
        print(json.dumps(anchor.to_dict(), indent=2))


if __name__ == "__main__":
    main()
