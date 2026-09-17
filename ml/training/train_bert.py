"""Fine-tune a lightweight DistilBERT classifier for phishing email detection.

This script is intentionally CPU-oriented and designed to run in a local dev or
build environment. It does not execute automatically during runtime and only
serves as the explicit training artifact for Phase 4.1.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = REPO_ROOT / "ml" / "datasets" / "public_email_threats.jsonl"
OUTPUT_PATH = REPO_ROOT / "ml" / "models" / "distilbert_email_classifier"


def _iter_rows() -> list[dict[str, Any]]:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    rows: list[dict[str, Any]] = []
    with DATASET_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                continue
            rows.append(item)
    return rows


def main() -> None:
    try:
        from datasets import load_dataset  # type: ignore
        from transformers import (  # type: ignore
            DistilBertForSequenceClassification,
            DistilBertTokenizerFast,
            Trainer,
            TrainingArguments,
        )
    except Exception as exc:  # pragma: no cover - explicit dependency gate
        raise RuntimeError(
            "Training requires transformers, datasets, and torch. Install: pip install transformers datasets torch"
        ) from exc

    rows = _iter_rows()
    if not rows:
        raise ValueError(f"No labeled examples found in {DATASET_PATH}")

    labels = sorted({str(item.get("label") or item.get("verdict") or "benign").lower() for item in rows})
    label_to_id = {label: index for index, label in enumerate(labels)}

    def normalize(row: dict[str, Any]) -> dict[str, Any]:
        text = str(row.get("text") or row.get("body") or row.get("content") or "").strip()
        label = str(row.get("label") or row.get("verdict") or "benign").lower()
        return {"text": text, "label": label_to_id.get(label, 0)}

    dataset = [normalize(item) for item in rows]
    texts = [row["text"] for row in dataset]
    labels_list = [row["label"] for row in dataset]

    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    tokenized = tokenizer(texts, padding=True, truncation=True, max_length=256, return_tensors="pt")

    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=len(labels),
    )

    if not OUTPUT_PATH.exists():
        OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    args = TrainingArguments(
        output_dir=str(OUTPUT_PATH / "checkpoints"),
        evaluation_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=2,
        weight_decay=0.01,
        save_strategy="epoch",
        logging_steps=50,
        report_to=[],
    )

    train_dataset = {
        "input_ids": tokenized["input_ids"],
        "attention_mask": tokenized["attention_mask"],
        "labels": labels_list,
    }

    trainer = Trainer(model=model, args=args, train_dataset=train_dataset)
    trainer.train()
    trainer.save_model(str(OUTPUT_PATH))
    tokenizer.save_pretrained(str(OUTPUT_PATH))
    (OUTPUT_PATH / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    print(f"Saved DistilBERT classifier to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
