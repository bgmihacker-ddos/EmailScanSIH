"""Build a public email corpus aligned to the SIH email-threat detection scope.

This combines publicly available, reusable email corpora:
- SpamAssassin public corpus: spam/phishing-like messages and benign ham.
- Enron public mailbox corpus: legitimate enterprise email traffic.

The result is a single JSONL dataset for training a realistic, explainable email
classifier while keeping the problem statement anchored to email analysis rather
than generic breach telemetry.
"""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, Iterable, List

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _body_parts(message: Any) -> tuple[str, str, int]:
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachment_count = 0
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get("content-disposition") or "").lower()
        if "attachment" in disposition or part.get_filename():
            attachment_count += 1
            continue
        try:
            content = part.get_content()
        except Exception:
            content = ""
        if not isinstance(content, str):
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(content)
        elif part.get_content_type() == "text/plain":
            plain_parts.append(content)
    return "\n".join(plain_parts), "\n".join(html_parts), attachment_count


def _normalize_record(payload: Dict[str, Any], source: str, source_file: str) -> Dict[str, Any]:
    subject = str(payload.get("subject") or "")
    body = str(payload.get("body") or "")
    html_body = str(payload.get("html_body") or "")
    combined = f"{subject}\n{body}\n{html_body}"
    urls = list(dict.fromkeys(item.rstrip(".,;:!?\"')>") for item in _URL_RE.findall(combined)))
    record = {
        "label": str(payload.get("label") or "benign"),
        "subject": subject,
        "body": body,
        "html_body": html_body,
        "has_html": int(bool(html_body)),
        "url_count": len(urls),
        "attachment_count": int(payload.get("attachment_count") or 0),
        "source": source,
        "source_file": source_file,
    }
    if not record["body"] and not record["subject"] and not record["html_body"]:
        return {}
    return record


def load_spamassassin(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"SpamAssassin JSONL not found: {path}")
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            record = _normalize_record(payload, "spamassassin_public_corpus", str(payload.get("source_file") or path.name))
            if record:
                records.append(record)
    return records


def load_enron(path: Path, limit: int | None = None) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Enron corpus path not found: {path}")
    records: List[Dict[str, Any]] = []
    # Enron Maildir messages are normally extensionless files; retain common
    # mailbox extensions too for compatible public mirrors.
    candidates = [
        item for item in path.rglob("*")
        if item.is_file() and (not item.suffix or item.suffix == "." or item.suffix.lower() in {".eml", ".txt", ".mbx", ".msg"})
    ]
    def append_message(raw: bytes, source_file: str) -> bool:
        try:
            if len(raw) > 2_000_000:
                return False
            message = BytesParser(policy=policy.default).parsebytes(raw)
        except Exception:
            return False
        plain_text, html_body, attachment_count = _body_parts(message)
        subject = str(message.get("subject") or "")
        safe_content = f"{subject}\n{plain_text}\n{html_body}".strip()
        if not safe_content:
            return False
        combined = f"{subject}\n{plain_text}\n{html_body}"
        urls = list(dict.fromkeys(item.rstrip(".,;:!?\"')>") for item in _URL_RE.findall(combined)))
        records.append({
            "label": "benign",
            "subject": subject,
            "body": plain_text,
            "html_body": html_body,
            "has_html": int(bool(html_body)),
            "url_count": len(urls),
            "attachment_count": attachment_count,
            "source": "enron_public_corpus",
            "source_file": source_file,
        })
        return True

    enron_records = 0
    for file_path in sorted(candidates):
        enron_records += int(append_message(file_path.read_bytes(), str(file_path)))
        if limit is not None and enron_records >= limit:
            return records

    # Windows cannot open the archive's trailing-dot filenames after extraction.
    archive = path.parent.parent / f"{path.parent.name}.tgz" if path.name == "maildir" else path.parent / f"{path.name}.tgz"
    if enron_records == 0 and archive.exists():
        with tarfile.open(archive, mode="r:gz") as handle:
            for member in handle:
                if not member.isfile():
                    continue
                stream = handle.extractfile(member)
                if stream is None:
                    continue
                if append_message(stream.read(), member.name):
                    enron_records += 1
                    if limit is not None and enron_records >= limit:
                        break
    return records


def build_dataset(spamassassin_path: Path, enron_root: Path | None, output_path: Path, enron_limit: int | None = None) -> Dict[str, int]:
    records: List[Dict[str, Any]] = []
    records.extend(load_spamassassin(spamassassin_path))
    if enron_root is not None:
        records.extend(load_enron(enron_root, limit=enron_limit))
    if not records:
        raise ValueError("No records were generated for the public training corpus")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    counts: Dict[str, int] = {}
    for record in records:
        counts[record["label"]] = counts.get(record["label"], 0) + 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a public-email dataset for the SIH email threat model")
    parser.add_argument("--spamassassin", type=Path, default=Path("ml/datasets/real/spamassassin.jsonl"))
    parser.add_argument("--enron-root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("ml/datasets/real/public_email_threats.jsonl"))
    parser.add_argument("--enron-limit", type=int, default=None)
    args = parser.parse_args()

    counts = build_dataset(args.spamassassin, args.enron_root, args.output, args.enron_limit)
    print(json.dumps({"output": str(args.output), "counts": counts}, indent=2))


if __name__ == "__main__":
    main()
