import pytest
from unittest.mock import patch, MagicMock
from app.detection.bert_classifier import (
    BertEmailClassifier,
    get_bert_classifier,
    _unavailable,
    MODEL_VERSION
)

def test_unavailable_fallback_shape():
    """Test the structure of the fallback dictionary."""
    res = _unavailable("test_error", "cpu")
    assert res["status"] == "unavailable"
    assert res["model"] == MODEL_VERSION
    assert res["device"] == "cpu"
    assert res["inference_active"] is False
    assert res["fallback_active"] is True
    assert res["error"] == "test_error"
    assert "feature_families" in res

def test_device_selection_force():
    """Test forcing cpu/cuda device string."""
    # Force CPU
    clf_cpu = BertEmailClassifier(model_path="dummy", force_device="cpu")
    assert clf_cpu._device_id == -1
    assert clf_cpu.device == "cpu"

    # Force CUDA - even without torch, force sets device ID appropriately
    clf_cuda = BertEmailClassifier(model_path="dummy", force_device="cuda")
    assert clf_cuda._device_id == 0
    assert clf_cuda.device == "cuda"

@patch("app.detection.bert_classifier.BertEmailClassifier._determine_device", return_value=-1)
def test_missing_transformers_graceful(mock_device):
    """Test graceful fallback when transformers is missing."""
    with patch("builtins.__import__", side_effect=ImportError("mocked import error")):
        clf = BertEmailClassifier()
        assert clf.is_available is False
        assert "transformers_unavailable" in str(clf._load_error)

        status = clf.get_status()
        assert status["status"] == "unavailable"
        assert status["inference_active"] is False
        assert status["fallback_active"] is True

        res = clf.predict("test text")
        assert res["status"] == "unavailable"

def test_missing_model_path_graceful():
    """Test graceful fallback when model artifact is missing."""
    class MockTransformers:
        def pipeline(self, *args, **kwargs):
            return None

    with patch.dict('sys.modules', {'transformers': MockTransformers()}):
        clf = BertEmailClassifier(model_path="/does/not/exist/ever")
        assert clf.is_available is False
        assert clf._load_error == "model_artifact_missing"

        res = clf.predict_email({"subject": "test", "body": "test"})
        assert res["status"] == "unavailable"

@patch("app.detection.bert_classifier.Path.exists", return_value=True)
def test_pipeline_load_error_graceful(mock_exists):
    """Test graceful fallback when pipeline creation throws an error."""
    class MockTransformers:
        def pipeline(self, *args, **kwargs):
            raise ValueError("Test pipeline error")

    with patch.dict('sys.modules', {'transformers': MockTransformers()}):
        clf = BertEmailClassifier(model_path="/fake/path")
        assert clf.is_available is False
        assert "load_error:ValueError" == clf._load_error

@patch("app.detection.bert_classifier.Path.exists", return_value=True)
def test_successful_predictions(mock_exists):
    """Test output shapes of successful prediction."""
    class MockTransformers:
        def pipeline(self, *args, **kwargs):
            def mock_pipeline_call(text):
                return [{"label": "phishing", "score": 0.95}]
            return mock_pipeline_call

    with patch.dict('sys.modules', {'transformers': MockTransformers()}):
        clf = BertEmailClassifier(model_path="/fake/path", force_device="cpu")
        assert clf.is_available is True

        res = clf.predict("Suspicious fake email here")
        assert res["status"] == "available"
        assert res["inference_active"] is True
        assert res["fallback_active"] is False
        assert res["label"] == "phishing"
        assert res["confidence"] == 0.95
        assert "distilbert" in res["features_used"][0]

        res_email = clf.predict_email({"subject": "Aler", "body": "Click here"})
        assert res_email["status"] == "available"
        assert res_email["label"] == "phishing"

def test_singleton_getter():
    """Test that get_bert_classifier returns a singleton."""
    clf1 = get_bert_classifier()
    clf2 = get_bert_classifier()
    assert clf1 is clf2
