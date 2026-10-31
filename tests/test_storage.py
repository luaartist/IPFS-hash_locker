import io
import pytest
from pathlib import Path
from ipfs_locker.storage.protocol import StorageBackend
from ipfs_locker.storage.local import LocalFSBackend
from ipfs_locker.storage.registry import StorageRegistry
from ipfs_locker.hasher import Blake3MmapHasher, compute_blake3


def test_storage_backend_protocol_conformance(tmp_path):
    backend = LocalFSBackend(tmp_path)
    assert isinstance(backend, StorageBackend)

    # Test put
    data = io.BytesIO(b"Tensor Checkpoint Matrix Stream Payload")
    uri = backend.put("checkpoints/epoch_001.bin", data)
    assert backend.exists("checkpoints/epoch_001.bin")
    assert backend.get_uri("checkpoints/epoch_001.bin").startswith("file://")

    # Test get
    recovered_stream = backend.get("checkpoints/epoch_001.bin")
    assert recovered_stream.read() == b"Tensor Checkpoint Matrix Stream Payload"

    # Test delete
    assert backend.delete("checkpoints/epoch_001.bin") is True
    assert backend.exists("checkpoints/epoch_001.bin") is False


def test_storage_registry():
    assert "local" in StorageRegistry.list_backends()
    local_backend = StorageRegistry.get_backend("local", root_dir="/tmp/test_storage")
    assert isinstance(local_backend, StorageBackend)


def test_blake3_mmap_hasher_multicore(tmp_path):
    large_file = tmp_path / "large_tensor_test.safetensors"
    # Write 5 MB binary test buffer
    chunk = b"0123456789ABCDEF" * 64 * 1024  # 1 MB
    large_file.write_bytes(chunk * 5)

    hasher = Blake3MmapHasher(max_workers=2)
    result = hasher.hash_file(large_file, chunk_size=1024 * 1024)

    assert result.size_bytes == 5 * 1024 * 1024
    assert len(result.blake3_hex) == 64
    assert result.cid.startswith("bafk2bzace")

    # Verify standard single-pass matches mmap parallel result
    single_pass_blake3 = compute_blake3(large_file)
    assert result.blake3_hex == single_pass_blake3
