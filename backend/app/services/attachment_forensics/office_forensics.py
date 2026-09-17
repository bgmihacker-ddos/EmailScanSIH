# AUDIT SCRIPT: Attachment Forensics - Office Forensics
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.office_forensics.OfficeForensics
# Data schemas: list of string indicators
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 4: Office/OLE/VBA Forensics."""

import io
import zipfile
import re
from typing import List

class OfficeForensics:
    _SUSPICIOUS_STRINGS = [
        (re.compile(b"powershell", re.IGNORECASE), "office_suspicious_powershell"),
        (re.compile(b"cmd\\.exe", re.IGNORECASE), "office_suspicious_cmd"),
        (re.compile(b"wscript", re.IGNORECASE), "office_suspicious_wscript"),
        (re.compile(b"certutil", re.IGNORECASE), "office_suspicious_certutil"),
        (re.compile(b"mshta", re.IGNORECASE), "office_suspicious_mshta"),
        (re.compile(b"regsvr32", re.IGNORECASE), "office_suspicious_regsvr32"),
    ]

    @staticmethod
    def inspect_ooxml(raw_bytes: bytes) -> List[str]:
        """Inspect OOXML (docx, xlsx, pptx, etc.) packages statically via zipfile."""
        indicators: List[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                namelist = zf.namelist()
                for name in namelist:
                    lower_name = name.lower()

                    # Macro check
                    if "vbaproject.bin" in lower_name:
                        indicators.append("ooxml_embedded_vba_macro")

                        # Check for suspicious strings inside the VBA project
                        try:
                            vba_data = zf.read(name)
                            for pattern, tag in OfficeForensics._SUSPICIOUS_STRINGS:
                                if pattern.search(vba_data) and tag not in indicators:
                                    indicators.append(tag)
                        except Exception:
                            pass

                    # External template injection check
                    if "_rels" in lower_name and lower_name.endswith(".rels"):
                        try:
                            rel_data = zf.read(name).decode("utf-8", errors="ignore")
                            if "TargetMode=\"External\"" in rel_data or "targetmode=\"external\"" in rel_data:
                                if "http" in rel_data:
                                    indicators.append("ooxml_external_template_or_link")
                        except Exception:
                            pass

        except Exception:
            pass
        return list(dict.fromkeys(indicators))
