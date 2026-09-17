"""Train the local explainable email classifier.

Usage from the repository root::

    python ml/training/train.py

The command reads only the controlled JSONL corpus and writes an ignored model
artifact. It never contacts external services and never runs during inference.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

import joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from ml.training.evaluate import evaluate_classifier
    from ml.training.features import STRUCTURAL_NAMES, record_to_features
except ImportError:
    from evaluate import evaluate_classifier
    from features import STRUCTURAL_NAMES, record_to_features

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = ROOT / "ml" / "datasets" / "controlled" / "emails.jsonl"
DEFAULT_ARTIFACT = ROOT / "ml" / "models" / "email_threat_tfidf_logreg.joblib"


def resolve_repo_path(path: Path) -> Path:
    if path.is_absolute():
        return path.resolve()

    cwd_candidate = (Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (ROOT / path).resolve()


def load_records(path: Path) -> List[Mapping[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    if not records:
        raise ValueError("The training corpus is empty")
    return records


def _matrix(
    records: List[Mapping[str, Any]],
    vectorizer: TfidfVectorizer,
    scaler: StandardScaler,
    fit: bool = False,
    prepared_by_id: Mapping[int, Mapping[str, Any]] | None = None,
):
    prepared = [
        prepared_by_id[id(record)] if prepared_by_id is not None else record_to_features(record)
        for record in records
    ]
    texts = [item["text"] for item in prepared]
    structures = np.asarray([
        [item["structure"][name] for name in STRUCTURAL_NAMES]
        for item in prepared
    ], dtype=float)
    text_matrix = vectorizer.fit_transform(texts) if fit else vectorizer.transform(texts)
    structural_matrix = scaler.fit_transform(structures) if fit else scaler.transform(structures)
    return hstack([text_matrix, structural_matrix], format="csr")


def _split_records(records: List[Mapping[str, Any]], labels: np.ndarray):
    """Split related source messages together to reduce corpus leakage."""
    groups = [str(record.get("source_file") or f"row-{index}") for index, record in enumerate(records)]
    if len(set(groups)) == len(groups):
        indices = np.arange(len(records))
        train_indices, test_indices = train_test_split(
            indices, test_size=0.25, random_state=20260907, stratify=labels
        )
        return train_indices, test_indices, "stratified_random"

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=20260907)
    train_indices, test_indices = next(splitter.split(records, labels, groups=groups))
    train_labels = set(labels[train_indices])
    test_labels = set(labels[test_indices])
    if train_labels != set(labels) or test_labels != set(labels):
        train_indices, test_indices = train_test_split(
            np.arange(len(records)), test_size=0.25, random_state=20260907, stratify=labels
        )
        return train_indices, test_indices, "stratified_random_fallback"
    return train_indices, test_indices, "grouped_source_file"


def train_model(
    dataset_path: Path = DEFAULT_DATASET,
    artifact_path: Path = DEFAULT_ARTIFACT,
    threshold: float = 0.40,
    max_samples: int | None = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    dataset_path = resolve_repo_path(dataset_path)
    artifact_path = resolve_repo_path(artifact_path)

    records = load_records(dataset_path)
    if max_samples and len(records) > max_samples:
        labels = {str(record["label"]) for record in records}
        per_class = max_samples // len(labels)
        selected = []
        for label in sorted(labels):
            selected.extend([record for record in records if str(record["label"]) == label][:per_class])
        records = selected
    prepared_by_id = {id(record): record_to_features(record) for record in records}
    labels = np.asarray([str(record["label"]) for record in records])
    train_indices, test_indices, split_strategy = _split_records(records, labels)
    train_records = [records[index] for index in train_indices]
    test_records = [records[index] for index in test_indices]

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=15000,
        sublinear_tf=True,
    )
    scaler = StandardScaler()

    # Evaluate on split
    train_features = _matrix(train_records, vectorizer, scaler, fit=True, prepared_by_id=prepared_by_id)
    test_features = _matrix(test_records, vectorizer, scaler, fit=False, prepared_by_id=prepared_by_id)
    classifier_eval = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=20260907, solver="lbfgs")
    classifier_eval.fit(train_features, [str(record["label"]) for record in train_records])
    metrics = evaluate_classifier(classifier_eval, test_features, [str(record["label"]) for record in test_records])

    # Train production model on full dataset
    full_vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=15000,
        sublinear_tf=True,
    )
    full_scaler = StandardScaler()
    full_features = _matrix(records, full_vectorizer, full_scaler, fit=True, prepared_by_id=prepared_by_id)
    classifier = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=20260907, solver="lbfgs")
    classifier.fit(full_features, labels)

    import datetime

    try:
        dataset_name = str(dataset_path.relative_to(ROOT))
    except ValueError:
        dataset_name = str(dataset_path)
    model_version = "tfidf-logreg-public-v3" if "public_email" in dataset_name else "tfidf-logreg-controlled-v2"

    artifact = {
        "artifact_version": 2,
        "model_version": model_version,
        "decision_threshold": threshold,
        "text_vectorizer": full_vectorizer,
        "structural_scaler": full_scaler,
        "classifier": classifier,
        "structural_names": list(STRUCTURAL_NAMES),
        "feature_families": ["subject_body_tfidf", "email_structure", "content_lexical"],
        "training_metadata": {
            "dataset": dataset_name,
            "sample_count": len(records),
            "max_samples": max_samples,
            "evaluation_sample_count": len(test_records),
            "classes": list(classifier.classes_),
            "random_state": 20260907,
            "split_strategy": split_strategy,
            "training_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "feature_version": 2,
            "metrics": metrics,
        },
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path, compress=3)
    metrics_path = artifact_path.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return artifact, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the controlled local email threat classifier")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--threshold", type=float, default=0.40,
                        help="Decision threshold to record in artifact metadata (default: 0.40)")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Optional balanced cap for large corpora")
    args = parser.parse_args()
    _, metrics = train_model(args.dataset, args.artifact, args.threshold, args.max_samples)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
