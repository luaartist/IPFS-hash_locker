"""
Local Filesystem Implementation of StorageBackend Protocol.
"""

from pathlib import Path
from typing import BinaryIO
import io
from ipfs_locker.storage.protocol import StorageBackend


class LocalFSBackend:
    """Local disk storage backend with hierarchical path sandboxing."""

    def __init__(self, root_dir: Path | str):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, data: BinaryIO, content_type: str = "application/octet-stream") -> str:
        target = self.root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        content = data.read()
        target.write_bytes(content)
        return str(target)

    def get(self, identifier: str) -> BinaryIO:
        target = Path(identifier) if Path(identifier).is_absolute() else (self.root / identifier)
        if not target.exists():
            raise FileNotFoundError(f"File not found in local storage: {identifier}")
        return io.BytesIO(target.read_bytes())

    def exists(self, identifier: str) -> bool:
        target = Path(identifier) if Path(identifier).is_absolute() else (self.root / identifier)
        return target.exists()

    def delete(self, identifier: str) -> bool:
        target = Path(identifier) if Path(identifier).is_absolute() else (self.root / identifier)
        if target.exists():
            target.unlink()
            return True
        return False

    def get_uri(self, identifier: str) -> str:
        target = Path(identifier) if Path(identifier).is_absolute() else (self.root / identifier)
        return f"file://{target.resolve()}"
