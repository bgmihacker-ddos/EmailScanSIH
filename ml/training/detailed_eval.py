"""Detailed evaluation script for candidates."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from scipy.sparse import hstack

import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "training"))
from evaluate import evaluate_classifier
from features import STRUCTURAL_NAMES, record_to_features

DATASET = ROOT / "ml" / "datasets" / "controlled" / "emails.jsonl"


def run_detailed():
    records = []
    with open(DATASET, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    labels = np.asarray([str(r["label"]) for r in records])
    indices = np.arange(len(records))
    train_indices, test_indices = train_test_split(
        indices, test_size=0.25, random_state=20260907, stratify=labels
    )

    train_records = [records[i] for i in train_indices]
    test_records = [records[i] for i in test_indices]

    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, sublinear_tf=True)
    scaler = StandardScaler()

    def get_mat(recs, fit=False):
        prepared = [record_to_features(r) for r in recs]
        texts = [i["text"] for i in prepared]
        structures = np.asarray([[i["structure"][name] for name in STRUCTURAL_NAMES] for i in prepared], dtype=float)
        tm = vectorizer.fit_transform(texts) if fit else vectorizer.transform(texts)
        sm = scaler.fit_transform(structures) if fit else scaler.transform(structures)
        return hstack([tm, sm], format="csr")

    train_features = get_mat(train_records, fit=True)
    test_features = get_mat(test_records, fit=False)
    y_train = [str(r["label"]) for r in train_records]
    y_test = [str(r["label"]) for r in test_records]

    clf = LogisticRegression(C=0.5, max_iter=1000, random_state=20260907)
    clf.fit(train_features, y_train)

    y_pred = clf.predict(test_features)
    classes = list(clf.classes_)

    print("=== Per-Class Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=classes, digits=4))

    print("=== Confusion Matrix (Classes: %s) ===" % classes)
    print(confusion_matrix(y_test, y_pred, labels=classes))

    metrics = evaluate_classifier(clf, test_features, y_test)
    print("Metrics summary:")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    run_detailed()
