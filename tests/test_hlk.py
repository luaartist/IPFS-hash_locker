import pytest
from pathlib import Path
import pymupdf
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidTag
import zstandard as zstd
import cbor2
import struct
import blake3
from ipfs_locker.hlk import HLKContainer
from ipfs_locker.crypto import generate_key, encrypt_bytes


def test_hlk_container_pack_unpack_roundtrip():
    payload = b"Sample Binary Stream Checkpoint - Partition 0-23 Matrix"
    passphrase = "MasterHLKSecretPassword2026!"
    signing_key = ed25519.Ed25519PrivateKey.generate()

    # Create HLK v2 container
    hlk_package = HLKContainer.create_package(
        payload,
        passphrase,
        signing_key=signing_key,
        cipher="aes-gcm-siv",
        extra_metadata={"project": "DistributedMesh-Phase1"},
    )
    assert len(hlk_package) > HLKContainer.HEADER_SIZE

    # Inspect manifest without decrypting
    manifest = HLKContainer.read_manifest(hlk_package)
    assert manifest["schema"] == "hlk-2"
    assert manifest["cipher"] == "aes-gcm-siv"
    assert manifest["kdf"] == "argon2id"
    assert manifest["compression"] == "zstd-19"
    assert manifest["payload_length"] == len(payload)
    assert manifest["author_key_id"] != ""
    assert manifest["extra_metadata"]["project"] == "DistributedMesh-Phase1"
    assert manifest["signature_algorithm"] == "Ed25519"

    # Verify detached public signature
    assert HLKContainer.verify_public_signature(hlk_package) is True

    # Unpack and decrypt
    decrypted_payload, unpacked_manifest = HLKContainer.unpack_package(hlk_package, passphrase)
    assert decrypted_payload == payload
    assert unpacked_manifest["schema"] == "hlk-2"


def test_hlk_container_with_pdf_forensics(tmp_path):
    pdf_path = tmp_path / "patent_doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), "Autonomous Multi-Agent Neural Synthesis Specification")
    doc.save(str(pdf_path))
    doc.close()

    raw_pdf_bytes = pdf_path.read_bytes()
    passphrase = "PDFSecretPassword999!"
    signing_key = ed25519.Ed25519PrivateKey.generate()

    hlk_package = HLKContainer.create_package(
        raw_pdf_bytes,
        passphrase,
        signing_key=signing_key,
        cipher="chacha20-poly1305",
        is_pdf=True,
        pdf_path=pdf_path,
    )

    manifest = HLKContainer.read_manifest(hlk_package)
    assert manifest["structural_digest"] != b""
    assert manifest["perceptual_digest"] != b""
    assert manifest["text_layer_digest"] != b""

    # Verify public signature
    assert HLKContainer.verify_public_signature(hlk_package) is True

    # Unpack and verify recovered PDF matches exactly
    recovered_bytes, _ = HLKContainer.unpack_package(hlk_package, passphrase)
    assert recovered_bytes == raw_pdf_bytes


def test_hlk_container_wrong_passphrase_fails():
    """Verify that unpacking with an incorrect passphrase fails closed with InvalidTag."""
    payload = b"Verification Payload Data Buffer"
    passphrase = "CorrectPassword123!"
    hlk_package = HLKContainer.create_package(payload, passphrase, cipher="aes-gcm-siv")

    with pytest.raises(InvalidTag):
        HLKContainer.unpack_package(hlk_package, "WrongPassword999!")


def test_hlk_container_tampered_ciphertext_fails_integrity():
    """Verify that tampering with ciphertext bytes triggers a fail-closed BLAKE3 digest mismatch."""
    payload = b"Authentic Unaltered Research Document Payload"
    passphrase = "IntegrityPassphrase2026!"
    hlk_package = HLKContainer.create_package(payload, passphrase, cipher="aes-gcm-siv")

    # Read manifest and calculate exact manifest offset directly from header
    _, _, manifest_len, _ = struct.unpack("<8sII48s", hlk_package[:HLKContainer.HEADER_SIZE])
    manifest_cbor = hlk_package[HLKContainer.HEADER_SIZE:HLKContainer.HEADER_SIZE + manifest_len]
    ciphertext = bytearray(hlk_package[HLKContainer.HEADER_SIZE + manifest_len:])

    # Mutate a byte in ciphertext
    ciphertext[20] ^= 0xFF

    header = struct.pack("<8sII48s", HLKContainer.MAGIC, HLKContainer.VERSION, manifest_len, b"\x00" * 48)
    tampered_package = header + manifest_cbor + bytes(ciphertext)

    with pytest.raises(ValueError, match="Ciphertext integrity verification failed: BLAKE3 digest mismatch"):
        HLKContainer.unpack_package(tampered_package, passphrase)


def test_hlk_container_tampered_signature_fails_verification():
    """Verify that tampering with any signed manifest attribute invalidates the Ed25519 signature."""
    payload = b"Artifact signed by author authority"
    passphrase = "SecureAuthorPassphrase!"
    signing_key = ed25519.Ed25519PrivateKey.generate()
    hlk_package = HLKContainer.create_package(payload, passphrase, signing_key=signing_key)
    assert HLKContainer.verify_public_signature(hlk_package) is True

    # Tamper with manifest created_at timestamp
    manifest = HLKContainer.read_manifest(hlk_package)
    manifest["created_at"] += 3600
    tampered_cbor = cbor2.dumps(manifest, canonical=True)
    header = struct.pack("<8sII48s", HLKContainer.MAGIC, HLKContainer.VERSION, len(tampered_cbor), b"\x00" * 48)

    _, _, orig_len, _ = struct.unpack("<8sII48s", hlk_package[:HLKContainer.HEADER_SIZE])
    payload_part = hlk_package[HLKContainer.HEADER_SIZE + orig_len:]
    tampered_package = header + tampered_cbor + payload_part

    assert HLKContainer.verify_public_signature(tampered_package) is False


def test_hlk_container_key_substitution_attack_prevented():
    """Verify that replacing author public_key with an attacker key fails public signature verification."""
    payload = b"Original author verified research thesis"
    passphrase = "LegitimateAuthorKey123"
    author_key = ed25519.Ed25519PrivateKey.generate()
    attacker_key = ed25519.Ed25519PrivateKey.generate()

    hlk_package = HLKContainer.create_package(payload, passphrase, signing_key=author_key)
    assert HLKContainer.verify_public_signature(hlk_package) is True

    # Attacker attempts to swap in their own public key and resign
    manifest = HLKContainer.read_manifest(hlk_package)
    manifest["public_key"] = attacker_key.public_key().public_bytes_raw()

    # Re-sign with attacker's key but retain author_key_id
    unsigned_manifest = {
        k: v for k, v in manifest.items()
        if k not in ("signature", "signature_algorithm")
    }
    canonical_bytes = cbor2.dumps(unsigned_manifest, canonical=True)
    manifest["signature"] = attacker_key.sign(HLKContainer.DOMAIN_SEPARATOR_V2 + canonical_bytes)
    manifest_cbor = cbor2.dumps(manifest, canonical=True)

    header = struct.pack("<8sII48s", HLKContainer.MAGIC, HLKContainer.VERSION, len(manifest_cbor), b"\x00" * 48)
    _, _, orig_len, _ = struct.unpack("<8sII48s", hlk_package[:HLKContainer.HEADER_SIZE])
    payload_part = hlk_package[HLKContainer.HEADER_SIZE + orig_len:]
    attack_package = header + manifest_cbor + payload_part

    # Verification must fail because author_key_id fingerprint does not match attacker's public key
    assert HLKContainer.verify_public_signature(attack_package) is False


def test_hlk_container_legacy_v1_backward_compatibility():
    """Verify that HLKContainer can still read and unpack legacy HLKv1 containers."""
    payload = b"Legacy HLKv1 Encrypt-then-Compress Artifact"
    passphrase = "LegacySecretPassword2024!"
    cipher = "aes-gcm-siv"

    # Construct a legacy HLKv1 container (Encrypt-then-Compress)
    aad_data = {"magic": "484c4b7631000000", "version": 1}
    aad_bytes = cbor2.dumps(aad_data)
    ciphertext = encrypt_bytes(payload, passphrase, cipher=cipher, associated_data=aad_bytes)
    ct_blake3 = blake3.blake3(ciphertext).digest()

    compressor = zstd.ZstdCompressor(level=19)
    compressed_payload = compressor.compress(ciphertext)

    manifest = {
        "schema": "hlk-1",
        "cipher": cipher,
        "ct_blake3": ct_blake3,
        "aad_bytes": aad_bytes,
        "signature_algorithm": "none",
        "public_key": b"",
        "signature": b"",
        "timestamp_utc": 1700000000,
        "extra_metadata": {},
    }
    manifest_cbor = cbor2.dumps(manifest)
    header = struct.pack("<8sII48s", b"HLKv1\x00\x00\x00", 1, len(manifest_cbor), b"\x00" * 48)
    legacy_package = header + manifest_cbor + compressed_payload

    # Read manifest
    read_mf = HLKContainer.read_manifest(legacy_package)
    assert read_mf["schema"] == "hlk-1"

    # Unpack legacy package
    unpacked, _ = HLKContainer.unpack_package(legacy_package, passphrase)
    assert unpacked == payload


def test_hlk_container_invalid_header_fails():
    """Verify that corrupted magic bytes or truncated headers are rejected immediately."""
    with pytest.raises(ValueError, match="truncated header"):
        HLKContainer.read_manifest(b"too_short_header")

    bad_magic = b"NOT_HLK\x00" + b"\x00" * 56
    with pytest.raises(ValueError, match="Invalid HLK magic bytes"):
        HLKContainer.read_manifest(bad_magic)
