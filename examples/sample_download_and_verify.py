"""
Example: Downloading encrypted package from IPFS and recovering/verifying hashes.
"""

from pathlib import Path
from ipfs_locker.crypto import unpack_and_decrypt_bundle
from ipfs_locker.hasher import compute_file_hash
from ipfs_locker.ipfs_client import IPFSClient

def main():
    cid = "QmExampleCID"
    bundle_path = Path("downloaded_bundle.zip.enc")

    # If IPFS is active, download by CID:
    # client = IPFSClient()
    # client.download_file(cid, bundle_path)

    # Decrypt and unpack:
    if bundle_path.exists():
        manifest = unpack_and_decrypt_bundle(bundle_path, "recovered_files", "MySuperSecurePassphrase")
        print("[+] Manifest recovered:", manifest)
        for filename, expected_hash in manifest.get("file_hashes", {}).items():
            actual = compute_file_hash(Path("recovered_files") / filename)
            print(f"File: {filename} -> {'MATCH' if actual == expected_hash else 'MISMATCH'}")

if __name__ == "__main__":
    main()
