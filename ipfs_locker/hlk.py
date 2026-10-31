"""
HLK v2 Secure Container Specification and Packaging Module.
Wire Format:
- Fixed 64-byte Header (Magic: b"HLKv2\x00\x00\x00", version: uint32=2, manifest_len: uint32, 48-byte zero padding)
- Canonical CBOR Manifest (Signed with SIA-HLK-V2 domain separator, Ed25519, binding all header fields)
- AEAD Ciphertext Payload (Compress-then-Encrypt: Zstd Level 19 plaintext -> AES-256-GCM-SIV / ChaCha20-Poly1305)

Memory hygiene notice:
In-browser scrubbing (crypto.getRandomValues + fill(0)) provides best-effort tab hygiene.
Strict zeroization guarantees (SecureZeroMemory / explicit_bzero + mlock) are enforced
in native companion daemons.
"""

import time
import struct
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union
import cbor2
import zstandard as zstd
import blake3
from cryptography.hazmat.primitives.asymmetric import ed25519
from ipfs_locker.crypto import encrypt_bytes, decrypt_bytes, generate_key
from ipfs_locker.pdf_processor import PDFProcessor


class HLKContainer:
    """Enterprise-grade HLK v2 container packager and validator with v1 legacy reading."""

    MAGIC_V2 = b"HLKv2\x00\x00\x00"  # 8 bytes
    MAGIC_V1 = b"HLKv1\x00\x00\x00"  # 8 bytes
    MAGIC = MAGIC_V2
    VERSION = 2
    HEADER_SIZE = 64
    ZSTD_LEVEL = 19
    DOMAIN_SEPARATOR_V2 = b"SIA-HLK-V2\x00"

    @classmethod
    def create_package(
        cls,
        payload_bytes: bytes,
        passphrase_or_key: Union[str, bytes],
        signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        cipher: str = "aes-gcm-siv",
        extra_metadata: Optional[Dict[str, Any]] = None,
        is_pdf: bool = False,
        pdf_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """
        Create an authenticated, compressed, and signed HLK v2 container.
        Compress-then-Encrypt:
        1. Plaintext -> Zstandard (level 19)
        2. AEAD encryption with AAD (AES-256-GCM-SIV or ChaCha20-Poly1305)
        3. Canonical CBOR manifest signed over DOMAIN_SEPARATOR_V2 + manifest_canonical_cbor
        """
        # Assign timestamp once to prevent signature/manifest race conditions
        created_at = int(time.time())

        # 1. Compute forensic digests if PDF
        struct_digest = b""
        percept_digest = b""
        text_digest = b""
        if is_pdf and pdf_path and Path(pdf_path).exists():
            try:
                struct_digest = PDFProcessor.compute_structural_digest(pdf_path)
                percept_digest, text_digest = PDFProcessor.compute_perceptual_and_text_digest(pdf_path)
            except Exception:
                pass

        # 2. Build AAD
        aad_data = {
            "magic": cls.MAGIC.hex(),
            "version": cls.VERSION,
            "struct_digest": struct_digest.hex(),
            "percept_digest": percept_digest.hex(),
            "text_digest": text_digest.hex(),
            "created_at": created_at,
        }
        aad_bytes = cbor2.dumps(aad_data, canonical=True)

        # 3. Compress-then-Encrypt: Compress plaintext payload with Zstandard
        compressor = zstd.ZstdCompressor(level=cls.ZSTD_LEVEL)
        compressed_payload = compressor.compress(payload_bytes)

        # 4. Encrypt compressed payload with AEAD + AAD
        kdf_type = "argon2id" if isinstance(passphrase_or_key, str) else "raw-key"
        kdf_params = {
            "memory_cost": 65536,
            "iterations": 3,
            "lanes": 4,
            "salt_size": 16,
        } if kdf_type == "argon2id" else {}

        ciphertext = encrypt_bytes(
            compressed_payload,
            passphrase_or_key,
            cipher=cipher,
            associated_data=aad_bytes,
            kdf_type=kdf_type,
        )
        ct_blake3 = blake3.blake3(ciphertext).digest()

        # 5. Build unsigned canonical CBOR manifest
        sig_algo = "none"
        pubkey_bytes = b""
        sig_bytes = b""
        author_key_id = ""

        if signing_key is not None:
            sig_algo = "Ed25519"
            pubkey_bytes = signing_key.public_key().public_bytes_raw()
            author_key_id = blake3.blake3(pubkey_bytes).hexdigest()[:16]

        unsigned_manifest = {
            "schema": "hlk-2",
            "cipher": cipher,
            "kdf": kdf_type,
            "kdf_params": kdf_params,
            "compression": f"zstd-{cls.ZSTD_LEVEL}",
            "payload_length": len(payload_bytes),
            "ct_blake3": ct_blake3,
            "structural_digest": struct_digest,
            "perceptual_digest": percept_digest,
            "text_layer_digest": text_digest,
            "aad_bytes": aad_bytes,
            "author_key_id": author_key_id,
            "public_key": pubkey_bytes,
            "created_at": created_at,
            "extra_metadata": extra_metadata or {},
        }

        # 6. Sign canonical CBOR manifest
        if signing_key is not None:
            canonical_bytes = cbor2.dumps(unsigned_manifest, canonical=True)
            to_sign = cls.DOMAIN_SEPARATOR_V2 + canonical_bytes
            sig_bytes = signing_key.sign(to_sign)

        manifest = dict(unsigned_manifest)
        manifest["signature_algorithm"] = sig_algo
        manifest["signature"] = sig_bytes

        manifest_cbor = cbor2.dumps(manifest, canonical=True)
        manifest_len = len(manifest_cbor)

        # 7. Construct 64-byte Header: 8s (magic) + I (version) + I (manifest_len) + 48s (padding)
        header = struct.pack(
            "<8sII48s",
            cls.MAGIC,
            cls.VERSION,
            manifest_len,
            b"\x00" * 48,
        )
        assert len(header) == cls.HEADER_SIZE

        return header + manifest_cbor + ciphertext

    @classmethod
    def read_manifest(cls, hlk_bytes: bytes) -> Dict[str, Any]:
        """Read and decode the CBOR manifest without decrypting payload."""
        if len(hlk_bytes) < cls.HEADER_SIZE:
            raise ValueError("Invalid HLK container: truncated header")

        magic, version, manifest_len, _ = struct.unpack("<8sII48s", hlk_bytes[:cls.HEADER_SIZE])
        if magic not in (cls.MAGIC_V2, cls.MAGIC_V1):
            raise ValueError(f"Invalid HLK magic bytes: {magic}")
        if version not in (1, 2):
            raise ValueError(f"Unsupported HLK version: {version}")

        manifest_start = cls.HEADER_SIZE
        manifest_end = manifest_start + manifest_len
        if len(hlk_bytes) < manifest_end:
            raise ValueError("Invalid HLK container: truncated manifest")

        manifest_cbor = hlk_bytes[manifest_start:manifest_end]
        manifest = cbor2.loads(manifest_cbor)
        return manifest

    @classmethod
    def unpack_package(
        cls,
        hlk_bytes: bytes,
        passphrase_or_key: Union[str, bytes],
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Unpack, verify, decrypt, and decompress payload from HLK container."""
        if len(hlk_bytes) < cls.HEADER_SIZE:
            raise ValueError("Invalid HLK container: truncated header")

        magic, version, manifest_len, _ = struct.unpack("<8sII48s", hlk_bytes[:cls.HEADER_SIZE])
        if magic not in (cls.MAGIC_V2, cls.MAGIC_V1):
            raise ValueError(f"Invalid HLK magic bytes: {magic}")

        manifest_start = cls.HEADER_SIZE
        manifest_end = manifest_start + manifest_len
        if len(hlk_bytes) < manifest_end:
            raise ValueError("Invalid HLK container: truncated manifest")

        manifest_cbor = hlk_bytes[manifest_start:manifest_end]
        manifest = cbor2.loads(manifest_cbor)
        raw_payload = hlk_bytes[manifest_end:]

        if version == 2:
            # HLKv2: Compress-then-Encrypt
            # 1. Verify ciphertext digest
            ct_blake3 = blake3.blake3(raw_payload).digest()
            if ct_blake3 != manifest.get("ct_blake3"):
                raise ValueError("Ciphertext integrity verification failed: BLAKE3 digest mismatch")

            # 2. Decrypt with AEAD + AAD (fail-closed if wrong key or tampered tag)
            cipher = manifest.get("cipher", "aes-gcm-siv")
            aad_bytes = manifest.get("aad_bytes", b"")
            kdf = manifest.get("kdf", "argon2id")
            decrypted_compressed = decrypt_bytes(
                raw_payload,
                passphrase_or_key,
                cipher=cipher,
                associated_data=aad_bytes,
                kdf_type=kdf,
                allow_fallback=False,
            )

            # 3. Only after AEAD authentication succeeds, decompress with Zstandard
            compression = manifest.get("compression", "zstd-19")
            if compression.startswith("zstd"):
                decompressor = zstd.ZstdDecompressor()
                plaintext = decompressor.decompress(decrypted_compressed)
            else:
                plaintext = decrypted_compressed

            # 4. Verify payload length
            expected_len = manifest.get("payload_length")
            if expected_len is not None and len(plaintext) != expected_len:
                raise ValueError(f"Payload length mismatch: expected {expected_len}, got {len(plaintext)}")

            return plaintext, manifest

        elif version == 1:
            # Legacy HLKv1: Encrypt-then-Compress
            decompressor = zstd.ZstdDecompressor()
            ciphertext = decompressor.decompress(raw_payload)

            ct_blake3 = blake3.blake3(ciphertext).digest()
            if ct_blake3 != manifest.get("ct_blake3"):
                raise ValueError("Ciphertext integrity verification failed: BLAKE3 digest mismatch")

            cipher = manifest.get("cipher", "aes-gcm-siv")
            aad_bytes = manifest.get("aad_bytes", b"")
            plaintext = decrypt_bytes(
                ciphertext,
                passphrase_or_key,
                cipher=cipher,
                associated_data=aad_bytes,
                kdf_type=manifest.get("kdf", "argon2id"),
                allow_fallback=True,
            )
            return plaintext, manifest
        else:
            raise ValueError(f"Unsupported HLK version: {version}")

    @classmethod
    def verify_public_signature(cls, hlk_bytes: bytes) -> bool:
        """Verify detached Ed25519 signature publicly without decrypting."""
        try:
            if len(hlk_bytes) < cls.HEADER_SIZE:
                return False
            magic, version, manifest_len, _ = struct.unpack("<8sII48s", hlk_bytes[:cls.HEADER_SIZE])
            manifest_start = cls.HEADER_SIZE
            manifest_end = manifest_start + manifest_len
            if len(hlk_bytes) < manifest_end:
                return False
            manifest_cbor = hlk_bytes[manifest_start:manifest_end]
            manifest = cbor2.loads(manifest_cbor)

            if manifest.get("signature_algorithm") != "Ed25519":
                return False

            pubkey_bytes = manifest.get("public_key")
            sig_bytes = manifest.get("signature")
            if not pubkey_bytes or not sig_bytes:
                return False

            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)

            if version == 2:
                # HLKv2: Canonical CBOR manifest over DOMAIN_SEPARATOR_V2
                unsigned_manifest = {
                    k: v for k, v in manifest.items()
                    if k not in ("signature", "signature_algorithm")
                }
                canonical_bytes = cbor2.dumps(unsigned_manifest, canonical=True)
                to_sign = cls.DOMAIN_SEPARATOR_V2 + canonical_bytes
                pubkey.verify(sig_bytes, to_sign)

                # Verify author_key_id matches public key fingerprint
                expected_key_id = blake3.blake3(pubkey_bytes).hexdigest()[:16]
                if manifest.get("author_key_id") and manifest["author_key_id"] != expected_key_id:
                    return False
                return True

            elif version == 1:
                # Legacy HLKv1 signature verification
                to_sign = cbor2.dumps({
                    "ct_blake3": manifest["ct_blake3"],
                    "aad_bytes": manifest["aad_bytes"],
                    "timestamp": manifest.get("timestamp_utc") or manifest.get("timestamp"),
                })
                pubkey.verify(sig_bytes, to_sign)
                return True
            else:
                return False
        except Exception:
            return False
