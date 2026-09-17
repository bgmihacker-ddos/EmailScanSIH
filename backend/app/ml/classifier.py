"""Phase 6I: Machine Learning Classifier Service.

This module remains for backward-compatible imports in tests and pipeline
code. Production inference lives in ``app.detection.ml_classifier``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from app.detection.ml_classifier import MLClassifier as _ProdMLClassifier


class MLClassifier(_ProdMLClassifier):
    """Backward-compatible alias.

    Notes:
    - Signature keeps an optional ``model_path`` override.
    - Behavior follows the production inference classifier.
    """

    def __init__(self, model_path: Optional[str] = None):
        super().__init__(model_path=model_path)


__all__ = ["MLClassifier"]
