"""
Storage module for IPFS Hash Locker.
Provides protocol abstractions and pluggable backends.
"""

from ipfs_locker.storage.protocol import StorageBackend
from ipfs_locker.storage.local import LocalFSBackend
from ipfs_locker.storage.registry import StorageRegistry

__all__ = ["StorageBackend", "LocalFSBackend", "StorageRegistry"]
