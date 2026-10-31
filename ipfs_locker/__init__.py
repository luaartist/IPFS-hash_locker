"""
IPFS Hash Locker
A cryptographic toolkit for encrypting payloads, uploading to IPFS,
and recovering & verifying file hashes and provenance upon download.
"""

from .crypto import encrypt_file, decrypt_file, encrypt_bytes, decrypt_bytes, generate_key
from .hasher import (
    compute_sha256,
    compute_blake2b,
    compute_file_hash,
    embed_hash_in_file,
    verify_file_hash,
    create_hash_companion,
    verify_hash_companion,
)
from .ipfs_client import IPFSClient
from .pdf_processor import PDFProcessor
from .provenance import ProvenanceEngine, TimestampAnchor

__version__ = "1.0.0"
__all__ = [
    "encrypt_file",
    "decrypt_file",
    "encrypt_bytes",
    "decrypt_bytes",
    "generate_key",
    "compute_sha256",
    "compute_blake2b",
    "compute_file_hash",
    "embed_hash_in_file",
    "verify_file_hash",
    "create_hash_companion",
    "verify_hash_companion",
    "IPFSClient",
    "PDFProcessor",
    "ProvenanceEngine",
    "TimestampAnchor",
]
