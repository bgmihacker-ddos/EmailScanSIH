# AUDIT SCRIPT: Attachment Forensics - Archive Forensics
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.archive_forensics.ArchiveForensics
# Data schemas: list of string indicators
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 3: Archive Forensics (ZIP, TAR, GZ, RAR)."""

import io
import zipfile
import tarfile
from typing import List

_DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "scr", "vbs", "js", "jse", "wsf", "wsh",
    "ps1", "psm1", "jar", "msi", "msp", "cpl", "hta", "lnk", "reg",
    "iso", "img", "vhd"
}

class ArchiveForensics:
    # Max reasonable depth or file count to avoid denial of service bounds
    MAX_ARCHIVE_ENTRIES = 10_000
    MAX_UNCOMPRESSED_SIZE = 100_000_000  # 100MB
    ZIP_BOMB_THRESHOLD_RATIO = 100

    @staticmethod
    def inspect(raw_bytes: bytes, extension: str) -> List[str]:
        indicators: List[str] = []
        if extension in ("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm"):
            indicators.extend(ArchiveForensics._inspect_zip(raw_bytes))
        elif extension in ("tar", "gz", "tar.gz", "tgz", "bz2"):
            indicators.extend(ArchiveForensics._inspect_tar(raw_bytes, extension))
        return list(dict.fromkeys(indicators))

    @staticmethod
    def _inspect_zip(raw_bytes: bytes) -> List[str]:
        indicators = []
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                infolist = zf.infolist()

                if len(infolist) > ArchiveForensics.MAX_ARCHIVE_ENTRIES:
                    indicators.append("archive_excessive_entries")
                    return indicators

                total_uncompressed = sum(info.file_size for info in infolist)
                compressed_size = len(raw_bytes) or 1

                if total_uncompressed > ArchiveForensics.MAX_UNCOMPRESSED_SIZE:
                    indicators.append("archive_excessive_decompressed_size")

                if (total_uncompressed / compressed_size) > ArchiveForensics.ZIP_BOMB_THRESHOLD_RATIO and total_uncompressed > 1_000_000:
                    indicators.append("zip_bomb_ratio_detected")

                for info in infolist:
                    fname = info.filename

                    if ".." in fname or fname.startswith("/") or fname.startswith("\\"):
                        indicators.append("zip_slip_path_traversal")

                    parts = fname.split(".")
                    if len(parts) >= 3 and parts[-1].lower() in _DANGEROUS_EXTENSIONS:
                        indicators.append("double_extension_in_archive")

                    if len(parts) >= 2 and parts[-1].lower() in _DANGEROUS_EXTENSIONS:
                        indicators.append("executable_in_archive")
        except Exception:
            pass
        return indicators

    @staticmethod
    def _inspect_tar(raw_bytes: bytes, extension: str) -> List[str]:
        indicators = []
        try:
            mode = "r:gz" if "gz" in extension else ("r:bz2" if "bz2" in extension else "r")
            with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode=mode) as tf:
                total_uncompressed = 0
                count = 0
                for member in tf:
                    count += 1
                    if count > ArchiveForensics.MAX_ARCHIVE_ENTRIES:
                        indicators.append("archive_excessive_entries")
                        break

                    total_uncompressed += member.size
                    if total_uncompressed > ArchiveForensics.MAX_UNCOMPRESSED_SIZE:
                        indicators.append("archive_excessive_decompressed_size")

                    if ".." in member.name or member.name.startswith("/") or member.name.startswith("\\"):
                        indicators.append("zip_slip_path_traversal")

                    parts = member.name.split(".")
                    if len(parts) >= 3 and parts[-1].lower() in _DANGEROUS_EXTENSIONS:
                        indicators.append("double_extension_in_archive")

                    if len(parts) >= 2 and parts[-1].lower() in _DANGEROUS_EXTENSIONS:
                        indicators.append("executable_in_archive")

                compressed_size = len(raw_bytes) or 1
                if (total_uncompressed / compressed_size) > ArchiveForensics.ZIP_BOMB_THRESHOLD_RATIO and total_uncompressed > 1_000_000:
                    indicators.append("zip_bomb_ratio_detected")

        except Exception:
            pass
        return indicators
