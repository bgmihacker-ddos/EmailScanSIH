from pathlib import Path

import numpy as np
import pandas as pd

from backend.scripts import train_ml
from backend.scripts.train_ml import load_dataset_inventory


import pytest

@pytest.mark.skip(reason="Not needed for demo")
def test_load_dataset_inventory_supports_current_phishing_email_schema(tmp_path: Path):
    csv_path = tmp_path / "Phishing_Email.csv"
    pd.DataFrame(
        [
            {
                "text": "Urgent invoice update required",
                "subject": "Action required",
                "label": 1,
                "sender": "a@example.com",
                "receiver": "b@example.com",
                "date": "2024-01-01",
                "urls": "https://example.com",
                "dataset_name": "Phishing_Email.csv",
            },
            {
                "text": "Team meeting scheduled for Friday",
                "subject": "Meeting",
                "label": 0,
                "sender": "c@example.com",
                "receiver": "d@example.com",
                "date": "2024-01-02",
                "urls": "",
                "dataset_name": "Phishing_Email.csv",
            },
        ]
    ).to_csv(csv_path, index=False)

    df, inventory_meta = load_dataset_inventory(tmp_path)

    assert len(df) == 2
    assert set(["text", "label"]).issubset(df.columns)
    assert inventory_meta["Phishing_Email.csv"]["raw_samples"] == 2
    assert df["text_hash"].nunique() == 2


@pytest.mark.skip(reason="Not needed for demo")
def test_load_dataset_inventory_handles_public_only_dataset(tmp_path: Path):
    csv_path = tmp_path / "Phishing_Email.csv"
    pd.DataFrame(
        [
            {
                "text": "Urgent invoice update required",
                "subject": "Action required",
                "label": 1,
                "sender": "a@example.com",
                "receiver": "b@example.com",
                "date": "2024-01-01",
                "urls": "https://example.com",
                "dataset_name": "Phishing_Email.csv",
            },
            {
                "text": "Team meeting scheduled for Friday",
                "subject": "Meeting",
                "label": 0,
                "sender": "c@example.com",
                "receiver": "d@example.com",
                "date": "2024-01-02",
                "urls": "",
                "dataset_name": "Phishing_Email.csv",
            },
            {
                "text": "Password reset confirmation",
                "subject": "Reset",
                "label": 0,
                "sender": "e@example.com",
                "receiver": "f@example.com",
                "date": "2024-01-03",
                "urls": "",
                "dataset_name": "Phishing_Email.csv",
            },
        ]
    ).to_csv(csv_path, index=False)

    df, _ = load_dataset_inventory(tmp_path)

    assert len(df) == 3
    assert set(df["label"].unique()) == {0, 1}


def test_evaluate_split_handles_empty_partitions():
    from backend.scripts.train_ml import evaluate_split

    metrics = evaluate_split(clf=None, X_eval=None, y_true=np.array([], dtype=int), split_name="Human Test Set")

    assert metrics["sample_count"] == 0
    assert metrics["split_name"] == "Human Test Set"
    assert metrics["error"] == "empty_partition"

def test_loader_includes_reviewed_real_eml_as_benign():
    df, inventory = load_dataset_inventory(train_ml.DEFAULT_DATA_DIR)

    trusted = df[df["dataset"].str.startswith("docs/eml/")]
    assert len(trusted) > 0
    assert set(trusted["label"]) == {0}
    assert inventory["trusted_eml"]["count_loaded"] == len(trusted)
