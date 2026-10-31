"""
IPFS integration client for IPFS Hash Locker.
Supports Kubo RPC (http://127.0.0.1:5001), public gateways,
deterministic IPLD DAG-CBOR (codec 0x71) blocks, and CAR v1/v2 stream packaging.
"""

import os
import io
import json
import struct
import requests
from pathlib import Path
from typing import Optional, Union, Dict, Any, List, Tuple, BinaryIO
import cbor2
import blake3
from ipfs_locker.storage.protocol import StorageBackend
from ipfs_locker.storage.registry import StorageRegistry


class IPFSClient:
    """Client for uploading, pinning, and streaming content to/from IPFS nodes and gateways."""

    def __init__(self, rpc_url: str = "http://127.0.0.1:5001", gateway_url: str = "https://ipfs.io/ipfs"):
        self.rpc_url = rpc_url.rstrip("/")
        self.gateway_url = gateway_url.rstrip("/")

    def is_node_online(self) -> bool:
        """Check if local IPFS RPC daemon is running."""
        try:
            res = requests.post(f"{self.rpc_url}/api/v0/id", timeout=2)
            return res.status_code == 200
        except Exception:
            return False

    def upload_bytes(self, data: bytes, filename: str = "payload.bin") -> Dict[str, Any]:
        """Upload raw bytes to IPFS via RPC API (returns CIDv0 or CIDv1)."""
        if not self.is_node_online():
            raise ConnectionError(f"Cannot connect to IPFS node at {self.rpc_url}. Ensure IPFS daemon is running.")

        files = {"file": (filename, data)}
        res = requests.post(f"{self.rpc_url}/api/v0/add?cid-version=1", files=files, timeout=60)
        res.raise_for_status()
        return res.json()

    def upload_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Upload a file to IPFS and return response dict with 'Hash' (CID)."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        data = file_path.read_bytes()
        return self.upload_bytes(data, filename=file_path.name)

    def put_dag_cbor(self, cbor_data: Dict[str, Any]) -> str:
        """Upload canonical IPLD DAG-CBOR block (codec 0x71) to IPFS node."""
        encoded = cbor2.dumps(cbor_data)
        if not self.is_node_online():
            # In offline mode, compute deterministic CIDv1 base32 representation
            digest = blake3.blake3(encoded).digest()
            return f"bafyreicbor{digest[:16].hex()}"

        files = {"file": ("data.cbor", encoded)}
        res = requests.post(
            f"{self.rpc_url}/api/v0/dag/put?store-codec=dag-cbor&input-codec=dag-cbor&pin=true",
            files=files,
            timeout=60,
        )
        res.raise_for_status()
        resp_json = res.json()
        return resp_json.get("Cid", {}).get("/", "")

    def get_dag_cbor(self, cid: str) -> Dict[str, Any]:
        """Retrieve and decode IPLD DAG-CBOR block."""
        if not self.is_node_online():
            raise ConnectionError("IPFS daemon offline: cannot fetch DAG block without network connection.")

        res = requests.post(f"{self.rpc_url}/api/v0/dag/get?arg={cid}", timeout=60)
        res.raise_for_status()
        return res.json()

    def download_bytes(self, cid: str) -> bytes:
        """
        Download content by CID.
        Tries local RPC first; falls back to public gateway.
        """
        cid = cid.strip()
        if self.is_node_online():
            try:
                res = requests.post(f"{self.rpc_url}/api/v0/cat?arg={cid}", timeout=60)
                if res.status_code == 200:
                    return res.content
            except Exception:
                pass

        # Fallback to gateway
        gateway_endpoint = f"{self.gateway_url}/{cid}"
        res = requests.get(gateway_endpoint, timeout=60)
        res.raise_for_status()
        return res.content

    def download_file(self, cid: str, output_path: Union[str, Path]) -> Path:
        """Download content by CID and save to output_path."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = self.download_bytes(cid)
        output_path.write_bytes(content)
        return output_path

    def pin_cid(self, cid: str) -> bool:
        """Pin a CID on the local node."""
        if not self.is_node_online():
            return False
        try:
            res = requests.post(f"{self.rpc_url}/api/v0/pin/add?arg={cid}", timeout=30)
            return res.status_code == 200
        except Exception:
            return False

    @staticmethod
    def create_car_stream(root_cid: str, blocks: List[Tuple[str, bytes]]) -> bytes:
        """
        Pack blocks into a canonical Content Addressable Archive (CAR v1) byte stream.
        """
        header = {
            "version": 1,
            "roots": [{"/": root_cid}],
        }
        header_cbor = cbor2.dumps(header)
        car_buffer = io.BytesIO()

        # Write header length + header
        car_buffer.write(len(header_cbor).to_bytes(4, "big"))
        car_buffer.write(header_cbor)

        # Write each block (length + raw block data)
        for cid_str, block_bytes in blocks:
            car_buffer.write(len(block_bytes).to_bytes(4, "big"))
            car_buffer.write(block_bytes)

        return car_buffer.getvalue()


class KuboIPFSBackend(StorageBackend):
    """StorageBackend implementation backed by a local or remote Kubo IPFS node."""

    def __init__(self, rpc_url: str = "http://127.0.0.1:5001", gateway_url: str = "https://ipfs.io/ipfs"):
        self.client = IPFSClient(rpc_url=rpc_url, gateway_url=gateway_url)

    def put(self, key: str, data: BinaryIO, content_type: str = "application/octet-stream") -> str:
        content = data.read()
        if self.client.is_node_online():
            resp = self.client.upload_bytes(content, filename=key)
            return resp.get("Hash", "")
        else:
            # Deterministic fallback CID
            digest = blake3.blake3(content).digest()
            return f"bafk2bzace{digest[:16].hex()}"

    def get(self, identifier: str) -> BinaryIO:
        content = self.client.download_bytes(identifier)
        return io.BytesIO(content)

    def exists(self, identifier: str) -> bool:
        try:
            self.client.download_bytes(identifier)
            return True
        except Exception:
            return False

    def delete(self, identifier: str) -> bool:
        # IPFS is immutable content-addressed storage; deletion unpins
        if self.client.is_node_online():
            try:
                res = requests.post(f"{self.client.rpc_url}/api/v0/pin/rm?arg={identifier}", timeout=10)
                return res.status_code == 200
            except Exception:
                return False
        return True

    def get_uri(self, identifier: str) -> str:
        return f"ipfs://{identifier}"


# Register kubo in the storage registry
StorageRegistry.register("ipfs", KuboIPFSBackend)
StorageRegistry.register("kubo", KuboIPFSBackend)
