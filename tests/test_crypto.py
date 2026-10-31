import os
import pytest
from pathlib import Path
from ipfs_locker.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file,
    decrypt_file,
    package_and_encrypt_bundle,
    unpack_and_decrypt_bundle,
    generate_key,
    derive_key_argon2id,
    derive_key_pbkdf2,
    derive_session_keys,
    SessionCryptoEngine,
    get_cipher_engine,
)
from ipfs_locker.hasher import compute_sha256


def test_encrypt_decrypt_bytes_with_passphrase_argon2id():
    """Verify primary Argon2id (m=64MB, t=3, p=4) key derivation and AES-GCM encryption."""
    data = b"Hello, IPFS Hash Locker Robust Security with Argon2id!"
    passphrase = "SecretMasterPassword123!"
    encrypted = encrypt_bytes(data, passphrase, kdf_type="argon2id")
    assert encrypted != data
    decrypted = decrypt_bytes(encrypted, passphrase, kdf_type="argon2id")
    assert decrypted == data


def test_encrypt_decrypt_bytes_with_raw_key():
    data = b"Arbitrary binary data payload \x00\xff\xfe"
    key = generate_key()
    encrypted = encrypt_bytes(data, key)
    decrypted = decrypt_bytes(encrypted, key)
    assert decrypted == data


def test_aes_gcm_siv_cipher():
    """Verify AES-256-GCM-SIV (RFC 8452) nonce-misuse resistant cipher."""
    data = b"Sensitive model weights and tensor checkpoints"
    key = generate_key()
    aad = b"header-metadata-aad"
    encrypted = encrypt_bytes(data, key, cipher="aes-gcm-siv", associated_data=aad)
    assert encrypted != data
    decrypted = decrypt_bytes(encrypted, key, cipher="aes-gcm-siv", associated_data=aad)
    assert decrypted == data


def test_chacha20_poly1305_cipher():
    """Verify ChaCha20-Poly1305 (RFC 8439) high-throughput stream cipher."""
    data = b"ChaCha20-Poly1305 binary stream buffer"
    key = generate_key()
    encrypted = encrypt_bytes(data, key, cipher="chacha20-poly1305")
    assert encrypted != data
    decrypted = decrypt_bytes(encrypted, key, cipher="chacha20-poly1305")
    assert decrypted == data


def test_hkdf_session_key_fanout():
    """Verify HKDF-SHA256 session key fanout derives deterministic distinct subkeys."""
    master_key = generate_key()
    subkeys = derive_session_keys(master_key, num_keys=5, context=b"test-stream-session")
    assert len(subkeys) == 5
    assert len(set(subkeys)) == 5  # all distinct
    assert all(len(k) == 32 for k in subkeys)

    # Determinism
    subkeys2 = derive_session_keys(master_key, num_keys=5, context=b"test-stream-session")
    assert subkeys == subkeys2


def test_session_crypto_engine_chunks():
    """Verify SessionCryptoEngine encrypts and decrypts multi-chunk streams."""
    engine = SessionCryptoEngine("MasterSessionPassphrase", cipher="aes-gcm-siv")
    chunks = [f"Chunk data part {i}".encode() for i in range(4)]

    encrypted_chunks = [engine.encrypt_chunk(chunk, i) for i, chunk in enumerate(chunks)]
    decrypted_chunks = [engine.decrypt_chunk(enc, i) for i, enc in enumerate(encrypted_chunks)]

    assert decrypted_chunks == chunks


def test_legacy_pbkdf2_fallback():
    """Verify backward compatibility fallback when decrypting legacy PBKDF2 ciphertexts."""
    data = b"Legacy encrypted document payload"
    passphrase = "LegacyPassword2024"
    # Encrypt explicitly with legacy PBKDF2
    legacy_encrypted = encrypt_bytes(data, passphrase, kdf_type="pbkdf2")

    # Decrypt with explicit allow_fallback=True (should fallback to PBKDF2)
    decrypted = decrypt_bytes(legacy_encrypted, passphrase, allow_fallback=True)
    assert decrypted == data


def test_bundle_pack_unpack_roundtrip(tmp_path):
    f1 = tmp_path / "test1.txt"
    f2 = tmp_path / "test2.py"
    f1.write_text("Document 1 content", encoding="utf-8")
    f2.write_text("print('hello world')", encoding="utf-8")

    out_bundle = tmp_path / "bundle.zip.enc"
    passphrase = "test-passphrase"

    package_and_encrypt_bundle([f1, f2], out_bundle, passphrase, cipher="aes-gcm-siv", metadata={"project": "TestProject"})
    assert out_bundle.exists()

    extract_dir = tmp_path / "extracted"
    manifest = unpack_and_decrypt_bundle(out_bundle, extract_dir, passphrase, cipher="aes-gcm-siv")

    assert (extract_dir / "test1.txt").read_text(encoding="utf-8") == "Document 1 content"
    assert (extract_dir / "test2.py").read_text(encoding="utf-8") == "print('hello world')"
    assert manifest["project"] == "TestProject"
    assert manifest["cipher"] == "aes-gcm-siv"
    assert "test1.txt" in manifest["file_hashes"]
