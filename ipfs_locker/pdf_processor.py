"""
PDF processing and forensic inspection module for IPFS Hash Locker.
Modernized for pymupdf with dual-layer integrity verification:
1. Canonical structural COS object graph digest (BLAKE3 / SHA-256)
2. Deterministic 300 DPI grayscale perceptual rendering + text-layer bounding box digest.
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
import pymupdf
import blake3


class PDFProcessor:
    """Utility class for forensic inspection, structural tree hashing, and perceptual rendering."""

    @staticmethod
    def is_pymupdf_available() -> bool:
        return True

    @staticmethod
    def get_pdf_info(pdf_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract comprehensive structural metadata, page geometry, and cryptographic digests."""
        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")

        raw_bytes = pdf_path.read_bytes()
        doc = pymupdf.open(str(pdf_path))
        try:
            info = {
                "path": str(pdf_path),
                "filename": pdf_path.name,
                "size_bytes": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "blake3": blake3.blake3(raw_bytes).hexdigest(),
                "page_count": len(doc),
                "metadata": dict(doc.metadata),
                "is_encrypted": doc.is_encrypted,
                "permissions": doc.permissions,
            }

            pages = []
            for i, page in enumerate(doc):
                pages.append({
                    "page_number": i + 1,
                    "width": page.rect.width,
                    "height": page.rect.height,
                    "rotation": page.rotation,
                    "images_count": len(page.get_images()),
                })
            info["pages"] = pages
            return info
        finally:
            doc.close()

    @staticmethod
    def compute_structural_digest(pdf_path: Union[str, Path]) -> bytes:
        """Compute canonical COS object graph digest over indirect objects and streams."""
        doc = pymupdf.open(str(pdf_path))
        try:
            hasher = blake3.blake3()
            xref_len = doc.xref_length()
            for xref in range(1, xref_len):
                if doc.xref_is_stream(xref):
                    try:
                        stream_data = doc.xref_stream(xref)
                        hasher.update(b"stream:" + stream_data)
                    except Exception:
                        pass
                else:
                    obj_str = doc.xref_object(xref, compressed=True)
                    hasher.update(f"obj:{xref}:".encode("ascii") + obj_str.encode("utf-8", errors="replace"))
            return hasher.digest()
        finally:
            doc.close()

    @staticmethod
    def compute_perceptual_and_text_digest(pdf_path: Union[str, Path], dpi: int = 300) -> Tuple[bytes, bytes]:
        """
        Compute dual perceptual digests:
        - Deterministic 300 DPI grayscale pixel rasterization
        - Normalized text runs with exact bounding box coordinates
        """
        doc = pymupdf.open(str(pdf_path))
        try:
            perceptual_hasher = blake3.blake3()
            text_hasher = blake3.blake3()
            matrix = pymupdf.Matrix(dpi / 72.0, dpi / 72.0)

            for page in doc:
                # 1. Grayscale 300 DPI perceptual raster
                pix = page.get_pixmap(matrix=matrix, colorspace=pymupdf.csGRAY, alpha=False)
                perceptual_hasher.update(pix.samples)

                # 2. Text layout dictionary with bounding boxes
                text_dict = page.get_text("dict")
                for block in text_dict.get("blocks", []):
                    if "lines" in block:
                        for line in block["lines"]:
                            for span in line["spans"]:
                                text_hasher.update(span["text"].encode("utf-16be"))
                                bbox = span["bbox"]
                                text_hasher.update(f"{bbox[0]:.2f},{bbox[1]:.2f},{bbox[2]:.2f},{bbox[3]:.2f}".encode("ascii"))

            return perceptual_hasher.digest(), text_hasher.digest()
        finally:
            doc.close()

    @staticmethod
    def extract_page_hashes(pdf_path: Union[str, Path]) -> List[str]:
        """Compute SHA-256 hash for each rendered page text in the PDF."""
        doc = pymupdf.open(str(pdf_path))
        try:
            page_hashes = []
            for page in doc:
                text = page.get_text().encode("utf-8")
                page_hashes.append(hashlib.sha256(text).hexdigest())
            return page_hashes
        finally:
            doc.close()

    @staticmethod
    def verify_multimodal_integrity(
        pdf_path: Union[str, Path],
        expected_structural: bytes,
        expected_perceptual: bytes,
        expected_text: Optional[bytes] = None
    ) -> bool:
        """Verify structural COS tree and visual perceptual raster match expected digests."""
        struct = PDFProcessor.compute_structural_digest(pdf_path)
        if struct != expected_structural:
            return False
        percept, text = PDFProcessor.compute_perceptual_and_text_digest(pdf_path)
        if percept != expected_perceptual:
            return False
        if expected_text is not None and text != expected_text:
            return False
        return True
