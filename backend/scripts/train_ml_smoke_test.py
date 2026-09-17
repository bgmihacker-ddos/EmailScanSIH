#!/usr/bin/env python3
"""Quick smoke test for the email-threat ML trainer.

This script validates that the current dataset schema is compatible with the
training pipeline and that a minimal training run completes successfully.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
for candidate in (str(REPO_ROOT), str(REPO_ROOT / 'backend')):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from scripts.train_ml import DEFAULT_DATA_DIR, DEFAULT_MODEL_DIR, train_and_validate


def main() -> int:
    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DATA_DIR
    model_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_MODEL_DIR
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42
    threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.40

    data_dir = data_dir.resolve()
    model_dir = model_dir.resolve()

    print(f"Smoke check: data_dir={data_dir}")
    print(f"Smoke check: model_dir={model_dir}")

    required_files = ["Phishing_Email.csv"]
    missing_files = [name for name in required_files if not (data_dir / name).exists()]
    if missing_files:
        print(f"Missing required dataset files: {missing_files}")
        return 1

    df = pd.read_csv(data_dir / "Phishing_Email.csv")
    required_columns = {"text", "label"}
    missing_columns = sorted(required_columns - set(df.columns))
    if missing_columns:
        print(f"Dataset schema mismatch. Missing required columns: {missing_columns}")
        return 2

    label_counts = df["label"].value_counts().to_dict()
    print(f"Dataset rows: {len(df)}")
    print(f"Label counts: {label_counts}")

    try:
        artifact, metadata = train_and_validate(
            data_dir=data_dir,
            model_dir=model_dir,
            calibrate=True,
            seed=seed,
            threshold=threshold,
            force=False,
        )
    except Exception as exc:  # pragma: no cover - smoke test fail path
        print(f"Training smoke test failed: {exc}")
        return 3

    print(f"Smoke test passed. Model version: {metadata.get('model_version')}")
    print(f"Main test accuracy: {metadata.get('evaluation_metrics', {}).get('main_test', {}).get('accuracy')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
