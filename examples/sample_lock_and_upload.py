"""
Example: Locking files, encrypting into a bundle, and uploading to IPFS.
"""

from pathlib import Path
from ipfs_locker.crypto import package_and_encrypt_bundle
from ipfs_locker.ipfs_client import IPFSClient

def main():
    sample_doc = Path("sample.txt")
    sample_doc.write_text("Important research data", encoding="utf-8")

    enc_bundle, manifest = package_and_encrypt_bundle(
        files_to_pack=[sample_doc],
        output_zip_enc="research_package.zip.enc",
        key_or_passphrase="MySuperSecurePassphrase"
    )
    print(f"[+] Created encrypted bundle: {enc_bundle}")

    client = IPFSClient()
    if client.is_node_online():
        res = client.upload_file(enc_bundle)
        print(f"[+] Uploaded to IPFS CID: {res['Hash']}")
    else:
        print("[!] Local IPFS node offline. Ready for gateway/node upload.")

if __name__ == "__main__":
    main()
