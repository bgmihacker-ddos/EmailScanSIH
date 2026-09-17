import csv
import email
from email import policy
from pathlib import Path

INPUT_DIR = Path(r"docs/dataset/emll")
OUTPUT_FILE = Path(r"docs/dataset/epvme.csv")


def get_body(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        return "\n".join(parts)

    try:
        return msg.get_content()
    except Exception:
        return ""


count = 0
failed = 0

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["subject", "body", "label"])

    for path in INPUT_DIR.rglob("*.eml"):
        try:
            with path.open("rb") as eml_file:
                msg = email.message_from_binary_file(
                    eml_file,
                    policy=policy.default
                )

            subject = str(msg.get("Subject", ""))
            body = get_body(msg)

            if not subject and not body:
                continue

            writer.writerow([
                subject,
                body,
                1
            ])

            count += 1

            if count % 1000 == 0:
                print(f"Processed {count:,} emails...")

        except Exception as e:
            failed += 1

print()
print("=" * 50)
print(f"Processed : {count:,}")
print(f"Failed    : {failed:,}")
print(f"Output    : {OUTPUT_FILE}")
print("=" * 50)