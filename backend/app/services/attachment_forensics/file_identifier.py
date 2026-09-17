# AUDIT SCRIPT: Attachment Forensics - FileIdentifier
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.file_identifier.FileIdentifier
# Data schemas: forensic metadata dicts
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 2: Safe Attachment File Identification and Metadata."""

import hashlib
import math
from typing import Dict, Any, Optional

class FileIdentifier:
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate the Shannon entropy of a byte stream."""
        if not data:
            return 0.0

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        entropy = 0.0
        size = len(data)
        for count in counts:
            if count > 0:
                p = count / size
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def get_file_metadata(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Calculate forensic metadata without execution."""
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()

        magic_bytes = raw_bytes[:4].hex()
        entropy = FileIdentifier.calculate_entropy(raw_bytes)

        # Heuristic for high-entropy obfuscation
        is_high_entropy = entropy > 7.5

        return {
            "sha256": sha256,
            "md5": md5,
            "magic_bytes": magic_bytes,
            "entropy": entropy,
            "is_high_entropy": is_high_entropy,
        }
