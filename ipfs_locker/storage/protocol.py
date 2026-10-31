"""
StorageBackend Protocol and Base Interfaces for IPFS Hash Locker.
Decouples core package from cloud/vendor execution environments (Modal, S3, local disk, Kubo).
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable, BinaryIO, AsyncIterator, Dict, Any, Optional
from pathlib import Path
from contextlib import AbstractAsyncContextManager


@runtime_checkable
class StorageBackend(Protocol):
    """Zero lock-in abstract storage backend protocol."""

    def put(self, key: str, data: BinaryIO, content_type: str = "application/octet-stream") -> str:
        """Store synchronous byte stream and return content identifier or path URI."""
        ...

    def get(self, identifier: str) -> BinaryIO:
        """Retrieve binary stream for given identifier."""
        ...

    def exists(self, identifier: str) -> bool:
        """Check if an object exists in the storage backend."""
        ...

    def delete(self, identifier: str) -> bool:
        """Remove an object from storage backend."""
        ...

    def get_uri(self, identifier: str) -> str:
        """Return canonical URI format (e.g. ipfs://, file://, s3://, modal-volume://)."""
        ...
