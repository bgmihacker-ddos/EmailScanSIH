# AUDIT SCRIPT: Attachment Forensics - PDF Forensics
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.pdf_forensics.PdfForensics
# Data schemas: list of string indicators
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 5: PDF Structure & Action Forensics."""

import re
from typing import List

class PdfForensics:
    _PDF_SUSPICIOUS_TOKENS = [
        (re.compile(rb"/JavaScript|/JS\b", re.IGNORECASE), "pdf_embedded_javascript"),
        (re.compile(rb"/OpenAction\b", re.IGNORECASE), "pdf_open_action"),
        (re.compile(rb"/Launch\b", re.IGNORECASE), "pdf_launch_action"),
        (re.compile(rb"/EmbeddedFiles\b", re.IGNORECASE), "pdf_embedded_files"),
        (re.compile(rb"/URI\s*\([^)]+\)", re.IGNORECASE), "pdf_external_uri"),
        (re.compile(rb"/AcroForm\b", re.IGNORECASE), "pdf_acroform"),
        (re.compile(rb"/AA\b", re.IGNORECASE), "pdf_additional_actions"),
    ]

    @staticmethod
    def inspect(raw_bytes: bytes) -> List[str]:
        """Perform static token inspection on PDF byte streams."""
        indicators: List[str] = []
        for pattern, tag in PdfForensics._PDF_SUSPICIOUS_TOKENS:
            if pattern.search(raw_bytes):
                indicators.append(tag)
        return indicators
