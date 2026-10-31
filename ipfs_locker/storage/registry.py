"""
StorageBackend Dynamic Registry.
Allows pluggable storage engines without hard vendor dependencies.
"""

from typing import Dict, Type, Any
from ipfs_locker.storage.protocol import StorageBackend
from ipfs_locker.storage.local import LocalFSBackend


class StorageRegistry:
    """Dynamic registry for StorageBackend providers."""

    _backends: Dict[str, Type[StorageBackend]] = {
        "local": LocalFSBackend,
    }

    @classmethod
    def register(cls, name: str, backend_cls: Type[StorageBackend]) -> None:
        cls._backends[name.lower()] = backend_cls

    @classmethod
    def get_backend(cls, name: str, **kwargs: Any) -> StorageBackend:
        name_lower = name.lower()
        if name_lower not in cls._backends:
            raise KeyError(f"Storage backend '{name}' not registered. Available: {list(cls._backends.keys())}")
        return cls._backends[name_lower](**kwargs)

    @classmethod
    def list_backends(cls) -> list[str]:
        return list(cls._backends.keys())
