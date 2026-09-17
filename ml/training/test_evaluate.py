from types import SimpleNamespace

import numpy as np

from ml.training.evaluate import evaluate_classifier


class StubClassifier:
    classes_ = np.asarray(["bec", "benign", "phishing"])

    def predict(self, features):
        return np.asarray(["phishing", "benign", "bec"])


def test_evaluate_classifier_reports_per_class_and_binary_metrics():
    metrics = evaluate_classifier(
        StubClassifier(),
        SimpleNamespace(shape=(3, 1)),
        ["phishing", "benign", "suspicious"],
    )

    assert metrics["sample_count"] == 3
    assert set(metrics["per_class"]) == {"bec", "benign", "phishing"}
    assert set(metrics["binary_threat_metrics"]) == {"benign", "threat"}
    assert metrics["binary_threat_metrics"]["threat"]["support"] == 2