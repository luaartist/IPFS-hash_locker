import pytest
from pathlib import Path
from ipfs_locker.hasher import (
    compute_sha256,
    compute_blake2b,
    create_hash_companion,
    verify_hash_companion,
    embed_hash_in_file,
    verify_file_hash,
)

def test_compute_hashes():
    data = "Test string for hashing"
    sha = compute_sha256(data)
    blake = compute_blake2b(data)
    assert len(sha) == 64
    assert len(blake) == 64

def test_companion_hash_lifecycle(tmp_path):
    f = tmp_path / "sample.pdf"
    f.write_bytes(b"%PDF-1.4 Mock PDF Content")

    companion = create_hash_companion(f)
    assert companion.exists()

    is_valid, stored, computed = verify_hash_companion(f)
    assert is_valid is True
    assert stored == computed

    # Tamper with file
    f.write_bytes(b"%PDF-1.4 Tampered Content")
    is_valid_after, _, _ = verify_hash_companion(f)
    assert is_valid_after is False

def test_inline_hash_lifecycle(tmp_path):
    script = tmp_path / "test_script.py"
    script.write_text("def run():\n    return 42\n", encoding="utf-8")

    res = embed_hash_in_file(script)
    assert res is True

    is_valid, stored, computed = verify_file_hash(script)
    assert is_valid is True
    assert stored == computed
