"""Dependency-light PDF forensic report generation."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, Iterable


def _pdf_escape(value: Any) -> str:
    text = str(value or "").encode("ascii", "replace").decode("ascii")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


# PDF report generator updating with verification link
def _lines(analysis: Dict[str, Any]) -> Iterable[str]:
    yield "Email Threat Detection - Forensic Report"
    yield f"Analysis ID: {analysis.get('analysis_id', 'unknown')}"
    yield f"Verdict: {analysis.get('verdict', 'unknown')}"
    yield f"Risk score: {analysis.get('risk_score', 'unknown')} / 100"
    yield f"Severity: {analysis.get('severity', 'unknown')}"
    yield f"Verify at: /api/analysis/{analysis.get('analysis_id', 'unknown')}/verify-qr"
    yield ""
    yield "Executive summary"
    yield str(analysis.get("summary") or "No summary available.")
    yield ""
    integrity = analysis.get("evidence_integrity") if isinstance(analysis.get("evidence_integrity"), dict) else {}
    yield f"Raw email SHA-256: {integrity.get('raw_email_sha256', 'unavailable')}"
    yield ""
    yield "Structured evidence"
    evidence = analysis.get("evidence_ledger") or analysis.get("forensic_findings") or []
    yield str(evidence)


def generate_forensic_pdf(analysis_data: Dict[str, Any]) -> bytes:
    """Create a valid, portable PDF without requiring a native PDF runtime."""
    content_lines = []
    for line in _lines(analysis_data):
        content_lines.extend(textwrap.wrap(str(line), width=92) or [""])

    max_lines = 46
    pages = [content_lines[index:index + max_lines] for index in range(0, len(content_lines), max_lines)] or [[]]
    objects: list[bytes] = []

    def add_object(body: str | bytes) -> int:
        raw = body.encode("ascii", "replace") if isinstance(body, str) else body
        objects.append(raw)
        return len(objects)

    catalog_id = add_object("<< /Type /Catalog /Pages 2 0 R >>")
    pages_id = add_object(b"")
    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []
    for page_lines in pages:
        commands = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"]
        for line in page_lines:
            commands.append(f"({_pdf_escape(line)}) Tj")
            commands.append("0 -14 Td")
        commands.append("ET")
        stream = "\n".join(commands).encode("ascii", "replace")
        content_id = add_object(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
        page_id = add_object(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>")
        page_ids.append(page_id)
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    return bytes(output)
