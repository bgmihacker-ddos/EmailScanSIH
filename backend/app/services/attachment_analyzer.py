# AUDIT SCRIPT: Attachment Analyzer
# Importers/Callers: app.api.routes.analysis, app.detection.evidence_correlation
# Affected API: app.services.attachment_analyzer
# Data schemas: attachment analysis dicts
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 6G & Phase 9: Safe Attachment Static & Forensic Analysis.

Inspects attachment metadata, extensions, MIME types, double extensions,
RTL character obfuscation, archive structures, PDF structures, OOXML/Office structures,
and calculates cryptographic hashes without execution.
"""

import hashlib
import io
import logging
import zipfile
import re
from typing import Any, Dict, List, Optional
from .ocr_service import OCRIntelligenceService
from .attachment_forensics.file_identifier import FileIdentifier
from .attachment_forensics.archive_forensics import ArchiveForensics
from .attachment_forensics.office_forensics import OfficeForensics
from .attachment_forensics.pdf_forensics import PdfForensics
from .attachment_forensics.executable_forensics import ExecutableForensics
from .attachment_forensics.ioc_extractor import AttachmentIocExtractor

logger = logging.getLogger(__name__)

_DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "scr", "vbs", "js", "jse", "wsf", "wsh",
    "ps1", "psm1", "jar", "msi", "msp", "cpl", "hta", "lnk", "reg",
    "iso", "img", "vhd"
}

_MACRO_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm"
}

_LEGACY_OFFICE_EXTENSIONS = {
    "doc", "xls", "ppt"
}

_ARCHIVE_EXTENSIONS = {
    "zip", "rar", "7z", "tar", "gz", "bz2"
}

_BIDI_CHARS = {"‮", "‭", "‬", "‎", "‏"}

# PDF Static Suspicious Tokens
_PDF_SUSPICIOUS_TOKENS = [
    (re.compile(rb"/JavaScript|/JS\b", re.IGNORECASE), "pdf_embedded_javascript"),
    (re.compile(rb"/OpenAction\b", re.IGNORECASE), "pdf_open_action"),
    (re.compile(rb"/Launch\b", re.IGNORECASE), "pdf_launch_action"),
    (re.compile(rb"/EmbeddedFiles\b", re.IGNORECASE), "pdf_embedded_files"),
    (re.compile(rb"/URI\s*\([^)]+\)", re.IGNORECASE), "pdf_external_uri"),
]


class AttachmentAnalyzer:
    @staticmethod
    def _inspect_pdf_bytes(raw_bytes: bytes) -> List[str]:
        """Perform static token inspection on PDF byte streams."""
        return PdfForensics.inspect(raw_bytes)

    @staticmethod
    def _inspect_ooxml_bytes(raw_bytes: bytes) -> List[str]:
        """Inspect OOXML (docx, xlsx, pptx, etc.) packages statically via zipfile."""
        return OfficeForensics.inspect_ooxml(raw_bytes)

    @staticmethod
    def _inspect_archive_bytes(raw_bytes: bytes) -> List[str]:
        """Inspect archive safely bounded for decompression bombs and dangerous payloads."""
        return ArchiveForensics.inspect(raw_bytes, "zip")

    @staticmethod
    def analyze(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a list of email attachments statically and safely."""
        analyzed_list: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        extracted_iocs: List[Dict[str, Any]] = []
        high_risk_count = 0

        for att in attachments:
            filename = str(att.get("filename") or att.get("name") or "unknown")
            content_type = str(att.get("content_type") or att.get("type") or "application/octet-stream")
            size = att.get("size")
            extension = str(att.get("extension") or "").lower()

            if not extension and "." in filename:
                extension = filename.rsplit(".", 1)[-1].lower()

            # Hash calculation if raw bytes available and hashes missing
            sha256 = att.get("sha256")
            md5 = att.get("md5")
            raw_bytes = att.get("raw_bytes")
            entropy = None
            is_high_entropy = False
            magic_bytes = str(att.get("magic_bytes") or "")

            if raw_bytes and isinstance(raw_bytes, (bytes, bytearray)):
                meta = FileIdentifier.get_file_metadata(raw_bytes, filename)
                sha256 = sha256 or meta["sha256"]
                md5 = md5 or meta["md5"]
                magic_bytes = magic_bytes or meta["magic_bytes"]
                entropy = meta["entropy"]
                is_high_entropy = meta["is_high_entropy"]

                # Extract IOCs
                att_iocs = AttachmentIocExtractor.extract_iocs(raw_bytes, filename, sha256 or filename)
                extracted_iocs.extend(att_iocs)

            indicators: List[str] = []
            risk = "safe"

            # Entropy indicator
            if is_high_entropy:
                indicators.append("high_entropy_payload")

            # 1. RTL / Bidirectional Override Spoofing
            has_bidi = any(c in filename for c in _BIDI_CHARS)
            if has_bidi:
                indicators.append("rtl_override_spoofing")
                risk = "malicious"

            # 2. Multi-extension obfuscation (e.g. invoice.pdf.exe)
            clean_filename = filename
            for bc in _BIDI_CHARS:
                clean_filename = clean_filename.replace(bc, "")

            parts = clean_filename.split(".")
            if len(parts) >= 3:
                second_last = parts[-2].lower()
                last_ext = parts[-1].lower()
                if second_last in {"pdf", "txt", "doc", "docx", "jpg", "png", "xlsx"} and last_ext in _DANGEROUS_EXTENSIONS:
                    indicators.append("double_extension")
                    risk = "malicious"

            # 3. Magic bytes vs Extension mismatch
            is_executable_magic = magic_bytes.lower().startswith("4d5a")  # MZ header
            if is_executable_magic and extension not in _DANGEROUS_EXTENSIONS:
                indicators.append("executable_magic_mismatch")
                risk = "malicious"

            # 4. Dangerous Executable or Script Extension
            if extension in _DANGEROUS_EXTENSIONS or is_executable_magic:
                if "executable_extension" not in indicators:
                    indicators.append("executable_extension")
                risk = "malicious"
            elif extension in _MACRO_EXTENSIONS:
                indicators.append("macro_capable_document")
                if risk == "safe":
                    risk = "suspicious"
            elif extension in _ARCHIVE_EXTENSIONS:
                indicators.append("archive_extension")
                if raw_bytes:
                    arch_inds = ArchiveForensics.inspect(raw_bytes, extension)
                    indicators.extend(arch_inds)
                    if any(i in arch_inds for i in ("executable_in_archive", "zip_bomb_ratio_detected", "zip_slip_path_traversal")):
                        risk = "malicious"

            # 5. Deep Format Inspection (PDF, OOXML, PE, Script)
            if raw_bytes and isinstance(raw_bytes, (bytes, bytearray)):
                if extension == "pdf" or content_type == "application/pdf":
                    pdf_inds = PdfForensics.inspect(raw_bytes)
                    indicators.extend(pdf_inds)
                    if "pdf_embedded_javascript" in pdf_inds or "pdf_launch_action" in pdf_inds:
                        risk = "malicious"
                    elif pdf_inds and risk == "safe":
                        risk = "suspicious"
                elif extension in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm"):
                    ooxml_inds = OfficeForensics.inspect_ooxml(raw_bytes)
                    indicators.extend(ooxml_inds)
                    if "ooxml_embedded_vba_macro" in ooxml_inds or "ooxml_external_template_or_link" in ooxml_inds:
                        if risk == "safe":
                            risk = "suspicious"
                elif extension in ("ps1", "vbs", "js", "hta"):
                    script_inds = ExecutableForensics.inspect_script(raw_bytes, extension)
                    indicators.extend(script_inds)
                elif is_executable_magic or extension in ("exe", "dll", "scr"):
                    pe_inds = ExecutableForensics.inspect_pe(raw_bytes)
                    indicators.extend(pe_inds)

            if risk == "malicious":
                high_risk_count += 1

            analyzed_item = {
                "filename": filename,
                "content_type": content_type,
                "size": size,
                "sha256": sha256,
                "md5": md5,
                "entropy": entropy,
                "extension": extension,
                "risk_level": risk,
                "indicators": list(dict.fromkeys(indicators)),
            }

            # --- START OCR INTEGRATION ---
            if content_type.startswith("image/") and raw_bytes and isinstance(raw_bytes, (bytes, bytearray)):
                try:
                    ocr_result = OCRIntelligenceService.analyze_image(raw_bytes, filename)
                    analyzed_item["ocr_status"] = ocr_result.get("status")
                    if ocr_result.get("has_qr_codes"):
                        analyzed_item["qr_codes"] = ocr_result.get("qr_codes")
                        if "qr_code_detected" not in indicators:
                            indicators.append("qr_code_detected")
                            analyzed_item["indicators"] = list(dict.fromkeys(indicators))
                    if ocr_result.get("extracted_text"):
                        analyzed_item["extracted_text"] = ocr_result.get("extracted_text")
                except Exception as e:
                    logger.debug(f"OCR integration skipped or failed: {e}")
            # --- END OCR INTEGRATION ---

            analyzed_list.append(analyzed_item)

            if risk in ("malicious", "suspicious"):
                evidence = [f"Filename: {filename}", f"Type: {content_type}"]
                if sha256:
                    evidence.append(f"SHA256: {sha256}")
                if magic_bytes:
                    evidence.append(f"Magic: {magic_bytes}")
                if entropy is not None:
                    evidence.append(f"Entropy: {entropy:.2f}")
                if indicators:
                    evidence.append(f"Indicators: {', '.join(indicators)}")

                findings.append({
                    "finding_id": f"attachment.{filename}.risk",
                    "category": "attachment",
                    "title": f"Dangerous Attachment: {filename}" if risk == "malicious" else f"Suspicious Attachment: {filename}",
                    "description": f"Attachment '{filename}' (type: {content_type}, extension: .{extension}) exhibited security indicators: {', '.join(indicators)}.",
                    "severity": "high" if risk == "malicious" else "medium",
                    "confidence": 95,
                    "evidence": evidence,
                    "related_iocs": [filename] + ([sha256] if sha256 else []),
                    "evidence_class": "strong_risk_signal",
                    "risk_relevance": "risk_contributing",
                })

        return {
            "attachments": analyzed_list,
            "findings": findings,
            "extracted_iocs": extracted_iocs,
            "high_risk_count": high_risk_count,
            "total_count": len(analyzed_list),
        }
