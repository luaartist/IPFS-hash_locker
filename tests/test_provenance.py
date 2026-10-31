import pytest
from ipfs_locker.provenance import (
    ProvenanceEngine,
    TimestampAnchor,
    MerkleTree,
    OTSCommitment,
)


def test_provenance_anchor_generation():
    doc_content = b"Verification Specification Document Version 1.0"
    anchor = ProvenanceEngine.generate_anchor(doc_content)
    assert 0 <= anchor.anchor_id < 50
    assert anchor.document_hash is not None
    assert len(anchor.anchor_hash_256) == 64
    assert len(anchor.merkle_root) == 64
    assert "ots_commitment" in anchor.to_dict()

    is_verified = ProvenanceEngine.verify_anchor(anchor.to_dict(), doc_content)
    assert is_verified is True


def test_merkle_tree_construction_and_proofs():
    leaves = [
        b"Merkle Leaf 0 - Chunk 1",
        b"Merkle Leaf 1 - Chunk 2",
        b"Merkle Leaf 2 - Chunk 3",
        b"Merkle Leaf 3 - Chunk 4",
        b"Merkle Leaf 4 - Chunk 5",  # Odd count to test duplication handling
    ]
    tree = MerkleTree(leaves)
    root = tree.root
    assert len(root) == 64

    # Test inclusion proof for each leaf
    for i, leaf in enumerate(leaves):
        leaf_hash = tree.leaves[i]
        proof = tree.get_proof(i)
        assert MerkleTree.verify_proof(leaf_hash, proof, root) is True


def test_ots_commitment_generation():
    merkle_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    timestamp = 1755300000.0
    ots = OTSCommitment.create_commitment(merkle_root, timestamp)

    assert ots["version"] == 1
    assert ots["merkle_root"] == merkle_root
    assert ots["attestation_type"] == "BitcoinBlockHeaderCommitment"
    assert len(ots["commitment_hash"]) == 64


def test_batch_merkle_anchor():
    batch = [
        "dataset-chunk-00001-of-00004.bin",
        "dataset-chunk-00002-of-00004.bin",
        "dataset-chunk-00003-of-00004.bin",
        "dataset-chunk-00004-of-00004.bin",
    ]
    batch_anchor = ProvenanceEngine.generate_batch_merkle_anchor(batch)
    assert len(batch_anchor.merkle_root) == 64
    assert len(batch_anchor.anchor_hash_256) == 64
    assert batch_anchor.ots_commitment["merkle_root"] == batch_anchor.merkle_root
