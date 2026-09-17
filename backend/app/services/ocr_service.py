"""Phase 14 & 15: Safe QR Code decoding & OCR integration with OCR_NOT_AVAILABLE fallback."""

import logging
import io
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class OCRIntelligenceService:
    """Safe QR Code and OCR integration."""

    @staticmethod
    def analyze_image(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Attempt to extract QR codes and text from image attachments.

        Gracefully falls back to OCR_NOT_AVAILABLE if required libraries
        (Pillow, pyzbar, pytesseract) are not installed or native dependencies
        are missing.
        """
        result: Dict[str, Any] = {
            "status": "OCR_NOT_AVAILABLE",
            "qr_codes": [],
            "has_qr_codes": False,
            "extracted_text": None,
            "error": None
        }

        try:
            from PIL import Image
            import pyzbar.pyzbar as pyzbar
            import pytesseract
        except ImportError as e:
            logger.debug(f"OCR/QR libraries not available: {e}")
            result["error"] = "Libraries not installed."
            return result

        try:
            image = Image.open(io.BytesIO(raw_bytes))

            # Ensure safe image bounds to prevent DoS via decompression bombs
            if image.width * image.height > 25000000:  # ~25 Megapixels limit
                result["error"] = "Image dimensions exceed safe processing bounds."
                return result

            # Attempt QR decoding
            decoded_objects = pyzbar.decode(image)
            qrs = []
            for obj in decoded_objects:
                if obj.type == "QRCODE":
                    try:
                        qrs.append(obj.data.decode("utf-8"))
                    except Exception:
                        pass

            result["qr_codes"] = qrs
            if qrs:
                result["has_qr_codes"] = True

            # Attempt OCR (limited to 5MB images approximately by the dimensions check above)
            text = pytesseract.image_to_string(image)
            if text and text.strip():
                result["extracted_text"] = text.strip()

            result["status"] = "success"

        except Exception as e:
            logger.warning(f"OCR/QR processing failed for {filename}: {e}")
            result["error"] = str(e)

        return result
