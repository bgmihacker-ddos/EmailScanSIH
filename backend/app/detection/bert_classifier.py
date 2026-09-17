"""Optional DistilBERT inference wrapper for email threat classification.

The project keeps the existing TF-IDF pipeline as the default path, but this
module provides a drop-in transformer path when runtime dependencies and weights
are available. Missing dependencies degrade gracefully so the forensic pipeline
continues without breaking the product.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger(__name__)

_MODEL_ROOT = Path(__file__).resolve().parents[3] / "ml" / "models" / "distilbert_email_classifier"
MODEL_VERSION = "distilbert-email-classifier-v1"


def _device_name(device_id: int) -> str:
    return "cuda" if device_id >= 0 else "cpu"


def _unavailable(error: str = "missing_runtime", device: str = "cpu") -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "model": MODEL_VERSION,
        "device": device,
        "inference_active": False,
        "fallback_active": True,
        "label": "unknown",
        "confidence": 0.0,
        "probability": 0.0,
        "probabilities": {},
        "model_version": MODEL_VERSION,
        "features_used": [],
        "feature_families": ["transformer_classifier"],
        "top_contributing_features": [],
        "error": error,
    }


class BertEmailClassifier:
    """Load a DistilBERT model from the repository when dependencies are present."""

    def __init__(self, model_path: Optional[str | Path] = None, force_device: Optional[str] = None, load_model: bool = True):
        self.model_path = Path(model_path) if model_path else _MODEL_ROOT
        self._pipeline = None
        self._load_error: Optional[str] = None
        self._device_id: int = -1
        self._device_str: str = "cpu"
        self._force_device = force_device
        if not load_model:
            self._load_error = "bert_disabled"
            return
        self._load_model()

    def _determine_device(self) -> int:
        if self._force_device == "cuda":
            return 0
        if self._force_device == "cpu":
            return -1
        try:
            import torch
            if torch.cuda.is_available():
                return 0
        except Exception:
            pass
        return -1

    def _load_model(self) -> None:
        required_artifacts = (
            self.model_path / "config.json",
            self.model_path / "tokenizer.json",
        )
        if not self.model_path.exists() or not all(path.exists() for path in required_artifacts):
            self._load_error = "model_artifact_missing"
            if self._force_device in {"cpu", "cuda"}:
                self._device_id = self._determine_device()
                self._device_str = _device_name(self._device_id)
            return

        self._device_id = self._determine_device()
        self._device_str = _device_name(self._device_id)

        try:
            from transformers import pipeline  # type: ignore
        except Exception as exc:  # pragma: no cover - runtime optional dependency
            self._load_error = f"transformers_unavailable:{type(exc).__name__}"
            return

        try:
            self._pipeline = pipeline(
                "text-classification",
                model=str(self.model_path),
                tokenizer=str(self.model_path),
                device=self._device_id,
                top_k=None,
            )
        except Exception as exc:  # pragma: no cover - loading failure is non-blocking
            self._load_error = f"load_error:{type(exc).__name__}"
            self._pipeline = None

    @property
    def is_available(self) -> bool:
        return self._pipeline is not None

    @property
    def device(self) -> str:
        return self._device_str

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "available" if self.is_available else "unavailable",
            "model": MODEL_VERSION,
            "device": self._device_str,
            "inference_active": self.is_available,
            "fallback_active": not self.is_available,
            "error": self._load_error,
        }

    def predict(self, text: str) -> Dict[str, Any]:
        if self._pipeline is None:
            return _unavailable(self._load_error or "missing_runtime", device=self._device_str)
        try:
            cleaned_text = str(text or "")[:512].strip()
            if not cleaned_text:
                return _unavailable("empty_input", device=self._device_str)

            result = self._pipeline(cleaned_text)
            payload = result[0] if isinstance(result, list) else result
            if isinstance(payload, list):
                # When top_k=None, returns list of {'label': ..., 'score': ...}
                probs = {str(item.get("label", "unknown")).lower(): float(item.get("score", 0.0)) for item in payload if isinstance(item, dict)}
                top_item = max(payload, key=lambda x: x.get("score", 0.0)) if payload else {}
                label = str(top_item.get("label", "unknown")).lower()
                score = float(top_item.get("score", 0.0))
            elif isinstance(payload, dict):
                label = str(payload.get("label", "unknown")).lower()
                score = float(payload.get("score", 0.0))
                probs = {label: score}
            else:
                return _unavailable("invalid_pipeline_output", device=self._device_str)

            return {
                "status": "available",
                "model": MODEL_VERSION,
                "device": self._device_str,
                "inference_active": True,
                "fallback_active": False,
                "label": label,
                "confidence": score,
                "probability": score,
                "probabilities": probs,
                "model_version": MODEL_VERSION,
                "features_used": ["distilbert_embedding", "transformer_attention_mask"],
                "feature_families": ["transformer_classifier"],
                "top_contributing_features": [
                    {
                        "feature": "distilbert_context_window",
                        "description": "Transformer self-attention contextual representation over token sequence",
                        "contribution": score,
                    }
                ],
                "error": None,
            }
        except Exception as exc:  # pragma: no cover
            return _unavailable(f"inference_error:{type(exc).__name__}", device=self._device_str)

    def predict_email(self, email: Mapping[str, Any] | None) -> Dict[str, Any]:
        if not isinstance(email, Mapping):
            return _unavailable(self._load_error or "bad_payload", device=self._device_str)
        subject = str(email.get("subject") or "")
        body = str(email.get("plain_text") or email.get("html_body") or email.get("body") or "")
        text = " ".join(part for part in (subject, body) if part).strip()
        return self.predict(text)


_default_classifier: Optional[BertEmailClassifier] = None


def get_bert_classifier() -> BertEmailClassifier:
    global _default_classifier
    if _default_classifier is None:
        enabled = os.getenv("BERT_ENSEMBLE_ENABLED", "false").lower() == "true"
        _default_classifier = BertEmailClassifier(load_model=enabled)
    return _default_classifier
