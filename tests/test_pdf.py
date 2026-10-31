import pytest
from pathlib import Path
import pymupdf
from ipfs_locker.pdf_processor import PDFProcessor


def test_pdf_processor_with_valid_pdf(tmp_path):
    dummy_pdf = tmp_path / "valid.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), "IPFS Hash Locker Provenance Test Document")
    doc.save(str(dummy_pdf))
    doc.close()

    info = PDFProcessor.get_pdf_info(dummy_pdf)
    assert info["filename"] == "valid.pdf"
    assert "sha256" in info
    assert len(info["sha256"]) == 64
    assert info["page_count"] == 1
    assert "blake3" in info


def test_pdf_structural_and_perceptual_digests(tmp_path):
    pdf_path = tmp_path / "forensic_test.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Confidential Patent Specification Claim 1")
    doc.save(str(pdf_path))
    doc.close()

    # Structural COS digest
    struct_digest = PDFProcessor.compute_structural_digest(pdf_path)
    assert len(struct_digest) == 32

    # Perceptual & text digests
    percept_digest, text_digest = PDFProcessor.compute_perceptual_and_text_digest(pdf_path)
    assert len(percept_digest) == 32
    assert len(text_digest) == 32

    # Full multimodal verification
    is_valid = PDFProcessor.verify_multimodal_integrity(
        pdf_path,
        expected_structural=struct_digest,
        expected_perceptual=percept_digest,
        expected_text=text_digest,
    )
    assert is_valid is True


def test_pdf_processor_page_hashes(tmp_path):
    multi_page_pdf = tmp_path / "multipage.pdf"
    doc = pymupdf.open()
    p1 = doc.new_page()
    p1.insert_text((50, 50), "Page 1 Content")
    p2 = doc.new_page()
    p2.insert_text((50, 50), "Page 2 Content")
    doc.save(str(multi_page_pdf))
    doc.close()

    hashes = PDFProcessor.extract_page_hashes(multi_page_pdf)
    assert len(hashes) == 2
    assert hashes[0] != hashes[1]
