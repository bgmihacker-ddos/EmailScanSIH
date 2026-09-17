"""Evaluation helpers for the controlled email ML corpus."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Sequence

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)


def evaluate_classifier(classifier: Any, features: Any, labels: Sequence[str]) -> Dict[str, Any]:
    """Return deterministic, JSON-serializable held-out classification metrics."""
    predicted = classifier.predict(features)
    classes = [str(value) for value in classifier.classes_]
    matrix = confusion_matrix(labels, predicted, labels=classes)
    class_precision, class_recall, class_f1, class_support = precision_recall_fscore_support(
        labels,
        predicted,
        labels=classes,
        zero_division=0,
    )
    benign_labels = {"benign", "legitimate", "safe"}
    binary_labels = ["benign" if str(label).lower() in benign_labels else "threat" for label in labels]
    binary_predicted = ["benign" if str(label).lower() in benign_labels else "threat" for label in predicted]
    binary_precision, binary_recall, binary_f1, binary_support = precision_recall_fscore_support(
        binary_labels,
        binary_predicted,
        labels=["benign", "threat"],
        zero_division=0,
    )
    threshold_metrics = {}
    if hasattr(classifier, "predict_proba"):
        probabilities = classifier.predict_proba(features)
        class_names = [str(value).lower() for value in classifier.classes_]
        threat_indices = [index for index, name in enumerate(class_names) if name not in benign_labels]
        if threat_indices:
            threat_probability = probabilities[:, threat_indices].sum(axis=1)
            for threshold in (0.30, 0.40, 0.50, 0.60, 0.70):
                threshold_predicted = [
                    "threat" if value >= threshold else "benign"
                    for value in threat_probability
                ]
                threshold_metrics[str(threshold)] = {
                    "threat_precision": float(precision_score(binary_labels, threshold_predicted, pos_label="threat", zero_division=0)),
                    "threat_recall": float(recall_score(binary_labels, threshold_predicted, pos_label="threat", zero_division=0)),
                    "threat_f1": float(f1_score(binary_labels, threshold_predicted, pos_label="threat", zero_division=0)),
                    "threat_support": int(sum(label == "threat" for label in binary_labels)),
                }
    return {
        "sample_count": len(labels),
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision_macro": float(precision_score(labels, predicted, labels=classes, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(labels, predicted, labels=classes, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(labels, predicted, labels=classes, average="macro", zero_division=0)),
        "labels": classes,
        "confusion_matrix": matrix.tolist(),
        "per_class": {
            label: {
                "precision": float(class_precision[index]),
                "recall": float(class_recall[index]),
                "f1": float(class_f1[index]),
                "support": int(class_support[index]),
            }
            for index, label in enumerate(classes)
        },
        "binary_threat_metrics": {
            label: {
                "precision": float(binary_precision[index]),
                "recall": float(binary_recall[index]),
                "f1": float(binary_f1[index]),
                "support": int(binary_support[index]),
            }
            for index, label in enumerate(("benign", "threat"))
        },
        "threat_threshold_metrics": threshold_metrics,
    }
