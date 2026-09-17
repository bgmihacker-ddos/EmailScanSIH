"""Test suite for OCR Intelligence and QR Code decoding service (Phase 14 & 15)."""

import pytest
from app.services.ocr_service import OCRIntelligenceService


def test_ocr_service_graceful_fallback_without_libraries():
    """Verify that OCR and QR scanning gracefully handle missing native dependencies / invalid bytes."""
    fake_bytes = b"not an image bytes"
    result = OCRIntelligenceService.analyze_image(fake_bytes, "test.png")
    assert isinstance(result, dict)
    assert result["status"] in ("OCR_NOT_AVAILABLE", "success")
    assert "qr_codes" in result
    assert "has_qr_codes" in result
    assert "extracted_text" in result
