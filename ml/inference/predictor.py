"""Lightweight CLI / demo helper for offline inference using the trained artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.detection.ml_classifier import MLClassifier  # noqa: E402


def predict_text(text: str) -> dict:
    """Predict category for arbitrary raw text using the default model."""
    classifier = MLClassifier()
    return classifier.predict(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict threat category for sample text")
    parser.add_argument("text", nargs="?", default="Urgent: verify your password immediately to avoid suspension.")
    args = parser.parse_args()
    result = predict_text(args.text)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
