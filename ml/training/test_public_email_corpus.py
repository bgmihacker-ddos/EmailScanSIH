import json
from pathlib import Path

from import_public_email_corpus import build_dataset


def test_build_dataset_combines_public_email_sources(tmp_path):
    spam_path = tmp_path / "spamassassin.jsonl"
    spam_path.write_text(
        json.dumps({
            "label": "phishing",
            "subject": "Urgent action required",
            "body": "Verify your password immediately and login now.",
            "html_body": "",
            "attachment_count": 0,
            "source_file": "spam_example.eml",
        }) + "\n" + json.dumps({
            "label": "benign",
            "subject": "Team lunch",
            "body": "Please join us for lunch tomorrow.",
            "html_body": "",
            "attachment_count": 0,
            "source_file": "ham_example.eml",
        }) + "\n",
        encoding="utf-8",
    )

    enron_dir = tmp_path / "enron"
    enron_dir.mkdir()
    (enron_dir / "one.eml").write_text(
        "Subject: Quarterly report\n\nHello team, the report is ready and no action is required.\n",
        encoding="utf-8",
    )
    (enron_dir / "extensionless_message").write_text(
        "Subject: Procurement update\n\nThe supplier review is complete.\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "public_dataset.jsonl"
    counts = build_dataset(spam_path, enron_dir, output_path, enron_limit=2)

    assert counts["phishing"] >= 1
    assert counts["benign"] >= 3
    assert output_path.exists()
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {row["label"] for row in rows}
    assert {"phishing", "benign"}.issubset(labels)
