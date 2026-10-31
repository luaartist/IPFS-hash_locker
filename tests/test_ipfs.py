import pytest
from ipfs_locker.ipfs_client import IPFSClient, KuboIPFSBackend
from ipfs_locker.storage.protocol import StorageBackend
from ipfs_locker.storage.registry import StorageRegistry
import io


def test_ipfs_client_initialization():
    client = IPFSClient()
    assert client.rpc_url == "http://127.0.0.1:5001"
    assert client.gateway_url == "https://ipfs.io/ipfs"


def test_car_stream_creation():
    blocks = [
        ("bafyreicbor001", b"\xa1aqa1"),
        ("bafyreicbor002", b"\xa1arb1"),
    ]
    car_bytes = IPFSClient.create_car_stream("bafyreicbor001", blocks)
    assert len(car_bytes) > 0
    header_len = int.from_bytes(car_bytes[:4], "big")
    assert header_len > 0
    assert len(car_bytes) >= 4 + header_len


def test_kubo_backend_registry():
    backend = StorageRegistry.get_backend("ipfs")
    assert isinstance(backend, StorageBackend)
    assert isinstance(backend, KuboIPFSBackend)

    # Test put and roundtrip get
    payload = b"CAR Archive Stream Checkpoint Live Node Roundtrip"
    data = io.BytesIO(payload)
    cid = backend.put("car_root.car", data)
    assert cid.startswith(("bafk", "bafy", "Qm"))
    assert backend.get_uri(cid) == f"ipfs://{cid}"

    # If node is online, test get retrieval
    if backend.client.is_node_online():
        stream = backend.get(cid)
        assert stream.read() == payload
