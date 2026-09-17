"""Production ML inference for parsed emails.

Inference is deliberately optional: a missing or invalid artifact returns a
structured unavailable result and never prevents forensic scanning.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import joblib
import numpy as np
import sklearn
from scipy.sparse import hstack

from app.detection.ml_features import email_to_features, text_to_features


_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CONTROLLED_MODEL_PATH = _REPOSITORY_ROOT / "ml" / "models" / "email_threat_tfidf_logreg.joblib"
_PUBLIC_MODEL_PATH = _REPOSITORY_ROOT / "ml" / "models" / "email_threat_tfidf_logreg_public.joblib"
DEFAULT_MODEL_PATH = _PUBLIC_MODEL_PATH if _PUBLIC_MODEL_PATH.exists() else _CONTROLLED_MODEL_PATH
_MODEL_VERSION_FALLBACK = "tfidf-logreg-public-v3"
_EXPLANATION_STOPWORDS = {
    "about", "after", "again", "been", "click", "com", "email", "from", "have",
    "hello", "http", "https", "just", "mail", "message", "more", "please", "that",
    "this", "there", "their", "they", "user", "with", "your", "you",
}


def _unavailable(model_version: str = _MODEL_VERSION_FALLBACK) -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "label": "unknown",
        "confidence": 0.0,
        "probability": 0.0,
        "probabilities": {},
        "raw_threat_probability": None,
        "decision_label": "unknown",
        "decision_confidence": 0.0,
        "decision_reason": "model_unavailable",
        "model_version": model_version,
        "features_used": [],
        "feature_families": [],
        "top_contributing_features": [],
        "artifact_runtime": {
            "trained_with_sklearn": None,
            "runtime_sklearn": sklearn.__version__,
            "version_match": None,
        },
    }


class MLClassifier:
    """Load and run a pre-trained TF-IDF/logistic-regression artifact."""

    def __init__(self, model_path: Optional[str | os.PathLike[str]] = None):
        configured = model_path or os.getenv("EMAIL_THREAT_ML_MODEL_PATH")
        self.model_path = Path(configured) if configured else DEFAULT_MODEL_PATH
        self.model: Optional[Mapping[str, Any]] = None
        self.load_error: Optional[str] = None
        self._load_model()

    def _load_model(self) -> None:
        if not self.model_path.exists():
            self.load_error = "artifact_missing"
            return
        try:
            loaded = joblib.load(self.model_path)
            if not isinstance(loaded, Mapping):
                raise ValueError("model artifact must be a mapping")
            required = {"text_vectorizer", "structural_scaler", "classifier", "structural_names"}
            if not required.issubset(loaded):
                raise ValueError("model artifact is missing required components")
            self.model = loaded
        except Exception as exc:  # artifact failures must not break scanning
            self.model = None
            self.load_error = type(exc).__name__

    def _artifact_runtime_status(self) -> Dict[str, Any]:
        trained_version = None
        metadata = self.model.get("training_metadata", {}) if self.model else {}
        if isinstance(metadata, Mapping):
            trained_version = metadata.get("sklearn_version")
        return {
            "trained_with_sklearn": trained_version,
            "runtime_sklearn": sklearn.__version__,
            "version_match": trained_version in (None, sklearn.__version__),
        }

    def predict(self, text: str) -> Dict[str, Any]:
        """Backward-compatible text prediction without inferred structure."""
        return self._predict_features(text_to_features(text))

    def predict_email(self, email: Mapping[str, Any] | None) -> Dict[str, Any]:
        """Predict from parser output while retaining structural message signals."""
        return self._predict_features(email_to_features(email))

    def _predict_features(self, features: Mapping[str, Any]) -> Dict[str, Any]:
        if self.model is None or not str(features.get("text", "")).strip():
            return _unavailable(str(self.model.get("model_version", _MODEL_VERSION_FALLBACK)) if self.model else _MODEL_VERSION_FALLBACK)

        try:
            vectorizer = self.model["text_vectorizer"]
            scaler = self.model["structural_scaler"]
            classifier = self.model["classifier"]
            structural_names = list(self.model["structural_names"])
            text_vector = vectorizer.transform([str(features["text"])])
            structural_values = np.asarray([[features["structure"].get(name, 0) for name in structural_names]], dtype=float)
            structural_vector = scaler.transform(structural_values)
            vector = hstack([text_vector, structural_vector], format="csr")

            probabilities_array = classifier.predict_proba(vector)[0]
            classes = [str(value) for value in classifier.classes_]
            probabilities = {label: round(float(value), 6) for label, value in zip(classes, probabilities_array)}

            # Threshold-calibrated decision (recall-optimised for phishing)
            THREAT_THRESHOLD = 0.40
            threat_label = "phishing"  # the positive class
            threat_prob = probabilities.get(threat_label, 0.0)
            structure = features.get("structure", {})
            authentication_text = str(features.get("authentication_headers", "")).lower()
            authenticated_low_risk_guard = (
                "spf=pass" in authentication_text
                and "dkim=pass" in authentication_text
                and "dmarc=pass" in authentication_text
                and not structure.get("attachment_count")
                and not structure.get("reply_to_mismatch")
            )
            observable_threat_signal = any(
                structure.get(name, 0)
                for name in (
                    "has_urgency",
                    "has_financial",
                    "reply_to_mismatch",
                    "has_upi_spoof",
                    "has_gov_brand",
                    "has_hindi_urgency",
                    "url_count",
                    "attachment_count",
                )
            ) or bool(structure.get("has_html") and structure.get("has_cred"))

            # TF-IDF models can assign a high score to an unfamiliar neutral
            # token. Do not promote that outlier to phishing without a
            # corroborating message-structure signal.
            low_signal_guard = not observable_threat_signal
            if authenticated_low_risk_guard:
                label = "benign"
                confidence = max(1.0 - threat_prob, 0.5)
                decision_reason = "authenticated_low_risk_guard"
            elif threat_prob >= THREAT_THRESHOLD and not low_signal_guard:
                label = threat_label
                confidence = threat_prob
                decision_reason = "raw_probability_at_or_above_threshold_with_observable_signal"
            else:
                # pick the highest-probability non-threat class
                label = max(
                    (c for c in classes if c != threat_label),
                    key=lambda c: probabilities.get(c, 0.0),
                    default=classes[int(np.argmax(probabilities_array))],
                )
                confidence = probabilities.get(label, float(probabilities_array[int(np.argmax(probabilities_array))]))
                decision_reason = "low_signal_guard" if low_signal_guard else "highest_probability_class"
            predicted_index = classes.index(label) if label in classes else int(np.argmax(probabilities_array))
            explain_clf = self.model.get("base_classifier", classifier)
            contributions = self._contributions(vector, explain_clf, vectorizer, structural_names, predicted_index)
            return {
                "status": "available",
                "label": label,
                "confidence": confidence,
                "probability": confidence,
                "raw_threat_probability": threat_prob,
                "decision_label": label,
                "decision_confidence": confidence,
                "decision_reason": decision_reason,
                "probabilities": probabilities,
                "model_version": str(self.model.get("model_version", _MODEL_VERSION_FALLBACK)),
                "features_used": ["tf-idf", *structural_names],
                "feature_families": list(self.model.get("feature_families", ["subject_body_tfidf", "email_structure"])),
                "top_contributing_features": contributions,
                "decision_threshold": THREAT_THRESHOLD,
                "threat_probability": threat_prob,
                "low_signal_guard": low_signal_guard,
                "observable_threat_signal": observable_threat_signal,
                "authenticated_low_risk_guard": authenticated_low_risk_guard,
                "artifact_runtime": self._artifact_runtime_status(),
            }
        except Exception:
            return _unavailable(str(self.model.get("model_version", _MODEL_VERSION_FALLBACK)))

    @staticmethod
    def _contributions(vector: Any, classifier: Any, vectorizer: Any, structural_names: list[str], class_index: int) -> list[Dict[str, Any]]:
        coefficients = np.asarray(classifier.coef_)
        if len(classifier.classes_) == 2 and coefficients.shape[0] == 1:
            coefficient_row = coefficients[0] if class_index == 1 else -coefficients[0]
        else:
            coefficient_row = coefficients[class_index]
        values = vector.toarray()[0]
        names = list(vectorizer.get_feature_names_out()) + structural_names
        scored = [
            (name, float(value * weight))
            for name, value, weight in zip(names, values, coefficient_row)
            if value
            and value * weight > 0
            and (name in structural_names or (len(name) >= 4 and name.isalpha() and name not in _EXPLANATION_STOPWORDS))
        ]
        scored = [(name, float(value * weight)) for name, value, weight in zip(names, values, coefficient_row) if value and value * weight > 0]
        scored.sort(key=lambda item: item[1], reverse=True)
        if not scored:
            scored = [
                (name, float(value * weight))
                for name, value, weight in zip(names, values, coefficient_row)
                if name in structural_names and value and value * weight > 0
            ]
            scored.sort(key=lambda item: item[1], reverse=True)

        # Mappings for explainability
        explanation_map = {
            "has_urgency": "Suspicious urgency/action language",
            "has_cred": "Credential/account verification language",
            "has_financial": "Financial or payment-related language",
            "reply_to_mismatch": "Mismatched sender and Reply-To addresses",
            "html_text_ratio": "Anomalous HTML-to-text ratio",
            "url_count": "Presence of URLs",
            "unique_url_count": "Multiple unique URLs",
            "attachment_count": "Presence of attachments",
            "has_html": "HTML content formatting",
        }

        results = []
        for name, score in scored[:10]:
            if name in explanation_map:
                desc = explanation_map[name]
            elif name in structural_names:
                desc = f"Structural anomaly ({name.replace('_', ' ')})"
            else:
                desc = f"Content keyword matching threat profile: '{name}'"

            results.append({
                "feature": name,
                "description": desc,
                "contribution": round(score, 6)
            })

        return results[:12]



_DEFAULT_CLASSIFIER: Optional[MLClassifier] = None


def get_ml_classifier() -> MLClassifier:
    """Return the process-local classifier instance; never trains on request."""
    global _DEFAULT_CLASSIFIER
    if _DEFAULT_CLASSIFIER is None:
        _DEFAULT_CLASSIFIER = MLClassifier()
    return _DEFAULT_CLASSIFIER
