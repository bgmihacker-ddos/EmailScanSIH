# AUDIT SCRIPT: Attachment Forensics - Executable Forensics
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.executable_forensics.ExecutableForensics
# Data schemas: list of string indicators
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 6: Script & Executable Forensics (PE Parsing/Script Heuristics)."""

import re
from typing import List

class ExecutableForensics:
    _SUSPICIOUS_IMPORTS = [
        # Common suspicious APIs for malware
        b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread",
        b"LoadLibrary", b"GetProcAddress", b"ShellExecute"
    ]

    @staticmethod
    def inspect_script(raw_bytes: bytes, extension: str) -> List[str]:
        """Perform static script heuristic inspection."""
        indicators: List[str] = []
        try:
            text = raw_bytes.decode("utf-8", errors="ignore").lower()
            if extension in ("ps1", "psm1"):
                if "bypass" in text or "encodedcommand" in text or "iwr" in text:
                    indicators.append("script_suspicious_powershell_keywords")
            elif extension in ("vbs", "js", "hta"):
                if "eval" in text or "exec" in text or "unescape" in text:
                    indicators.append("script_suspicious_obfuscation")
        except Exception:
            pass
        return indicators

    @staticmethod
    def inspect_pe(raw_bytes: bytes) -> List[str]:
        """Perform basic PE signature and suspicious import inspection."""
        indicators: List[str] = []
        if raw_bytes[:2] != b"MZ":
            return indicators

        indicators.append("executable_pe_header")

        # Very basic check for suspicious imports in the binary
        for import_pattern in ExecutableForensics._SUSPICIOUS_IMPORTS:
            if import_pattern in raw_bytes:
                indicators.append(f"pe_suspicious_import_{import_pattern.decode()}")

        return indicators
