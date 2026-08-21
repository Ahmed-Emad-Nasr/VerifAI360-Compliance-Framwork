"""Tests for src/evidence_processor.py's content-based file signature validation
(README section 12, known-gap #5: 'file-type validation is extension-based only').
"""

import pytest

from src import evidence_processor as ep


def test_text_extension_has_no_signature_check(tmp_path):
    """Plain-text formats have no fixed byte signature by design — anything
    with one of these extensions should pass through untouched."""
    p = tmp_path / "notes.txt"
    p.write_text("literally anything")
    ep.validate_file_signature(str(p), "notes.txt")  # should not raise


def test_real_png_signature_is_accepted(tmp_path):
    p = tmp_path / "shot.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    ep.validate_file_signature(str(p), "shot.png")  # should not raise


def test_text_renamed_to_png_is_rejected(tmp_path):
    p = tmp_path / "shot.png"
    p.write_text("this is not actually a PNG file")
    with pytest.raises(ep.EvidenceSignatureError):
        ep.validate_file_signature(str(p), "shot.png")


def test_text_renamed_to_docx_is_rejected(tmp_path):
    p = tmp_path / "policy.docx"
    p.write_text("just plain text, not a real zip/docx container")
    with pytest.raises(ep.EvidenceSignatureError):
        ep.validate_file_signature(str(p), "policy.docx")


def test_real_docx_zip_signature_is_accepted(tmp_path):
    p = tmp_path / "policy.docx"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 20)  # real docx files are ZIP containers
    ep.validate_file_signature(str(p), "policy.docx")  # should not raise


def test_jpeg_signature_mismatch_is_rejected(tmp_path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"GIF89a" + b"\x00" * 20)  # wrong signature for a .jpg
    with pytest.raises(ep.EvidenceSignatureError):
        ep.validate_file_signature(str(p), "photo.jpg")
