"""
Cryptographic module for IPFS Hash Locker (Hardened Phase 1).
Implements:
- Argon2id (m=64MB, t=3, p=4) primary KDF
- HKDF-SHA256 Session Key Fanout for zero-overhead chunk streaming
- AES-256-GCM (RFC 5116)
- AES-256-GCM-SIV (RFC 8452 Nonce-Misuse-Resistant)
- ChaCha20-Poly1305 (RFC 8439)
- Seamless backward compatibility with legacy PBKDF2-HMAC-SHA256
"""

import os
import json
import zipfile
import io
from pathlib import Path
from typing import Tuple, Optional, Union, List, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# Parameter Constants (Wolfram Peer Review Spec)
SALT_SIZE = 16
NONCE_SIZE = 12
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_ITERATIONS = 3       # t=3
ARGON2_LANES = 4            # p=4
KEY_SIZE = 32               # 256-bit

PBKDF2_ITERATIONS = 200_000 # Legacy fallback


def generate_key() -> bytes:
    """Generate a random 256-bit (32-byte) key."""
    return os.urandom(KEY_SIZE)


def derive_key_argon2id(
    passphrase: str,
    salt: bytes,
    length: int = KEY_SIZE,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_cost: int = ARGON2_MEMORY_COST,
) -> bytes:
    """
    Derive a 256-bit key using Argon2id (m=64MB, t=3, p=4).
    Hardened against GPU/ASIC parallel brute-force attacks.
    """
    kdf = Argon2id(
        salt=salt,
        length=length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_key_pbkdf2(
    passphrase: str,
    salt: bytes,
    length: int = KEY_SIZE,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Derive a 256-bit key using legacy PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_key(passphrase: str, salt: bytes, kdf_type: str = "argon2id") -> bytes:
    """
    Derive a 256-bit key using the configured KDF.
    Defaults to Argon2id; supports 'pbkdf2' for legacy payload compatibility.
    """
    if kdf_type.lower() == "argon2id":
        return derive_key_argon2id(passphrase, salt)
    elif kdf_type.lower() == "pbkdf2":
        return derive_key_pbkdf2(passphrase, salt)
    else:
        raise ValueError(f"Unsupported KDF type: {kdf_type}")


def derive_session_keys(
    master_key: bytes,
    context: bytes = b"ipfs-hash-locker-v1-session",
    num_keys: int = 1,
    key_length: int = KEY_SIZE,
    info_prefix: bytes = b"chunk-key",
) -> List[bytes]:
    """
    Derive multiple chunk/session subkeys from a single master key using HKDF-SHA256.
    Allows high-throughput batch locking without re-running Argon2id per chunk.
    """
    subkeys = []
    for i in range(num_keys):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=context + b":" + info_prefix + b"-" + str(i).encode("utf-8"),
            backend=default_backend(),
        )
        subkeys.append(hkdf.derive(master_key))
    return subkeys


def get_cipher_engine(cipher_name: str, key: bytes):
    """Factory for authenticated encryption cipher engines."""
    name = cipher_name.lower().replace("_", "-")
    if name in ("aes-gcm", "aes256-gcm", "gcm"):
        return AESGCM(key)
    elif name in ("aes-gcm-siv", "aes256-gcm-siv", "siv"):
        return AESGCMSIV(key)
    elif name in ("chacha20-poly1305", "chacha20", "poly1305"):
        return ChaCha20Poly1305(key)
    else:
        raise ValueError(f"Unsupported cipher: {cipher_name}. Choose 'aes-gcm', 'aes-gcm-siv', or 'chacha20-poly1305'.")


class SessionCryptoEngine:
    """
    High-throughput session manager.
    Runs Argon2id once at session start, then fans out HKDF-SHA256 subkeys per chunk.
    """

    def __init__(self, key_or_passphrase: Union[bytes, str], cipher: str = "aes-gcm", kdf_type: str = "argon2id"):
        self.cipher_name = cipher
        if isinstance(key_or_passphrase, str):
            self.salt = os.urandom(SALT_SIZE)
            self.master_key = derive_key(key_or_passphrase, self.salt, kdf_type=kdf_type)
        else:
            self.salt = b"\x00" * SALT_SIZE
            self.master_key = key_or_passphrase

    def get_chunk_key(self, chunk_index: int) -> bytes:
        return derive_session_keys(self.master_key, num_keys=chunk_index + 1)[chunk_index]

    def encrypt_chunk(self, data: bytes, chunk_index: int, associated_data: Optional[bytes] = None) -> bytes:
        chunk_key = self.get_chunk_key(chunk_index)
        engine = get_cipher_engine(self.cipher_name, chunk_key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = engine.encrypt(nonce, data, associated_data)
        return nonce + ciphertext

    def decrypt_chunk(self, encrypted_chunk: bytes, chunk_index: int, associated_data: Optional[bytes] = None) -> bytes:
        if len(encrypted_chunk) < NONCE_SIZE + 16:
            raise ValueError("Encrypted chunk is truncated.")
        nonce = encrypted_chunk[:NONCE_SIZE]
        ciphertext = encrypted_chunk[NONCE_SIZE:]
        chunk_key = self.get_chunk_key(chunk_index)
        engine = get_cipher_engine(self.cipher_name, chunk_key)
        return engine.decrypt(nonce, ciphertext, associated_data)


def encrypt_bytes(
    data: bytes,
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
    associated_data: Optional[bytes] = None,
    kdf_type: str = "argon2id",
) -> bytes:
    """
    Encrypt plaintext bytes using specified AEAD cipher (AES-GCM, AES-GCM-SIV, or ChaCha20-Poly1305).
    Returns: salt (16 bytes) + nonce (12 bytes) + ciphertext + tag.
    """
    if isinstance(key_or_passphrase, str):
        salt = os.urandom(SALT_SIZE)
        key = derive_key(key_or_passphrase, salt, kdf_type=kdf_type)
    else:
        salt = b"\x00" * SALT_SIZE
        key = key_or_passphrase

    nonce = os.urandom(NONCE_SIZE)
    engine = get_cipher_engine(cipher, key)
    ciphertext = engine.encrypt(nonce, data, associated_data)
    return salt + nonce + ciphertext


def decrypt_bytes(
    encrypted_data: bytes,
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
    associated_data: Optional[bytes] = None,
    kdf_type: str = "argon2id",
    allow_fallback: bool = False,
) -> bytes:
    """
    Decrypt AEAD ciphertext.
    Expects: salt (16 bytes) + nonce (12 bytes) + ciphertext + tag.
    Fails closed with InvalidTag on decryption failure.
    Optional allow_fallback=True enables legacy unversioned PBKDF2 fallback.
    """
    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted data is too short or corrupted.")

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]

    if isinstance(key_or_passphrase, str):
        try:
            key = derive_key(key_or_passphrase, salt, kdf_type=kdf_type)
            engine = get_cipher_engine(cipher, key)
            return engine.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            # Fallback to PBKDF2 only if explicitly allowed for legacy unversioned data
            if allow_fallback and kdf_type.lower() == "argon2id":
                try:
                    fallback_key = derive_key_pbkdf2(key_or_passphrase, salt)
                    engine = get_cipher_engine(cipher, fallback_key)
                    return engine.decrypt(nonce, ciphertext, associated_data)
                except Exception:
                    pass
            raise
    else:
        key = key_or_passphrase
        engine = get_cipher_engine(cipher, key)
        return engine.decrypt(nonce, ciphertext, associated_data)


def encrypt_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
) -> str:
    """Encrypt a file and write to output_path."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    data = input_path.read_bytes()
    encrypted = encrypt_bytes(data, key_or_passphrase, cipher=cipher)
    output_path.write_bytes(encrypted)
    return str(output_path)


def decrypt_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
) -> str:
    """Decrypt a file and write to output_path."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    data = input_path.read_bytes()
    decrypted = decrypt_bytes(data, key_or_passphrase, cipher=cipher)
    output_path.write_bytes(decrypted)
    return str(output_path)


def package_and_encrypt_bundle(
    files_to_pack: list,
    output_zip_enc: Union[str, Path],
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
    metadata: Optional[dict] = None,
) -> Tuple[str, dict]:
    """
    Pack multiple files into an in-memory zip archive, inject manifest.json,
    encrypt the entire zip with specified cipher (default AES-256-GCM + Argon2id),
    and save as output_zip_enc.
    """
    zip_buffer = io.BytesIO()
    manifest = {}

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in files_to_pack:
            item_path = Path(item)
            if item_path.is_file():
                zf.write(item_path, arcname=item_path.name)
                import hashlib
                manifest[item_path.name] = hashlib.sha256(item_path.read_bytes()).hexdigest()

        if metadata is None:
            metadata = {}
        metadata["file_hashes"] = manifest
        metadata["cipher"] = cipher
        metadata["kdf"] = "argon2id" if isinstance(key_or_passphrase, str) else "raw-key"
        zf.writestr("manifest.json", json.dumps(metadata, indent=2))

    zip_bytes = zip_buffer.getvalue()
    encrypted_bytes = encrypt_bytes(zip_bytes, key_or_passphrase, cipher=cipher)

    output_path = Path(output_zip_enc)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted_bytes)
    return str(output_path), metadata


def unpack_and_decrypt_bundle(
    input_zip_enc: Union[str, Path],
    output_dir: Union[str, Path],
    key_or_passphrase: Union[bytes, str],
    cipher: str = "aes-gcm",
) -> dict:
    """
    Decrypt an encrypted zip bundle and extract files into output_dir.
    Returns the manifest dictionary containing original file hashes.
    """
    input_path = Path(input_zip_enc)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    encrypted_bytes = input_path.read_bytes()
    decrypted_zip_bytes = decrypt_bytes(encrypted_bytes, key_or_passphrase, cipher=cipher)

    zip_buffer = io.BytesIO(decrypted_zip_bytes)
    manifest = {}

    with zipfile.ZipFile(zip_buffer, "r") as zf:
        zf.extractall(output_dir)
        if "manifest.json" in zf.namelist():
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))

    return manifest
