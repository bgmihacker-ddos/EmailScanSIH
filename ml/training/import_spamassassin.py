"""Import the public SpamAssassin corpus into the local training contract.

Usage from the repository root:
    python ml/training/import_spamassassin.py --input-dir <extracted-corpus> \
        --output ml/datasets/real/spamassassin.jsonl

Expected input layout:
    <input-dir>/easy_ham/*
    <input-dir>/hard_ham/*
    <input-dir>/spam/*
"""

from __future__ import annotations

import argparse
import json
import re
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


def _record(path: Path, label: str) -> Dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    plain_text, html_body, attachment_count = _body_parts(message)
    subject = str(message.get("subject") or "")
    combined = f"{subject}\n{plain_text}\n{html_body}"
    urls = list(dict.fromkeys(item.rstrip(".,;:!?\"')>") for item in _URL_RE.findall(combined)))
    return {
        "label": label,
        "subject": subject,
        "body": plain_text,
        "html_body": html_body,
        "has_html": int(bool(html_body)),
        "url_count": len(urls),
        "attachment_count": attachment_count,
        "source": "spamassassin_public_corpus",
        "source_file": path.name,
    }


def import_corpus(input_dir: Path) -> List[Dict[str, Any]]:
    groups = (("easy_ham", "benign"), ("hard_ham", "benign"), ("spam", "phishing"))
    records: List[Dict[str, Any]] = []
    for directory_name, label in groups:
        directory = input_dir / directory_name
        if not directory.is_dir():
            raise ValueError(f"Missing corpus directory: {directory}")
        for path in sorted(item for item in directory.iterdir() if item.is_file()):
            try:
                records.append(_record(path, label))
            except Exception:
                continue
    if not records:
        raise ValueError("No parseable email records found")
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Import SpamAssassin public email corpus")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = import_corpus(args.input_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    counts: Dict[str, int] = {}
    for record in records:
        counts[record["label"]] = counts.get(record["label"], 0) + 1
    print(json.dumps({"output": str(args.output), "records": len(records), "labels": counts}, indent=2))


if __name__ == "__main__":
    main()
