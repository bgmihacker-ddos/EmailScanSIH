# ML Classifier Layer — Threat Classification, Explainability & Architecture

The ML subsystem provides a bounded, deterministic threat signal based on email content semantics and structural messaging signals. To ensure system reliability and deterministic safety during forensic analysis, the classifier operates strictly offline, using a local model artifact.

It does not employ open-ended LLM inference or make external API calls for classification.

---

## 1. Architecture

1. **Feature Extraction (`backend/app/detection/ml_features.py`)**
   Takes parsed email output from `EmailParser` to produce non-circular features:
   - TF-IDF with sublinear TF scaling (unigrams and bigrams) on combined subject + body.
   - Observable structural indicators (HTML presence, URL counts, unique URL counts, HTML-to-text ratio, attachment counts, subject/body length buckets).
   - Observable lexical / social engineering indicators (urgency/action patterns, credential request cues, financial/wire transfer keywords, sender vs. Reply-To mismatch).
   - *Constraint:* Never consumes risk scores, verdicts, or threat-intelligence outcomes produced later in the pipeline.

2. **Artifact Generation (`ml/training/train.py`)**
   Loads labelled controlled records, performs stratified 75/25 train/test splitting (`random_state=20260907`), fits TF-IDF vectorizer, standardizes structural/lexical features, fits a Logistic Regression model via scikit-learn, validates accuracy strictly on the held-out test split, and emits a versioned, compressed `joblib` artifact along with audit metrics.

3. **Inference (`backend/app/detection/ml_classifier.py`)**
   Loads the generated artifact once upon startup (cached locally).
   Returns calibrated probability distributions and maps the mathematical coefficient contributions into human-readable SOC analyst explanations.

4. **Risk Engine Integration (`backend/app/detection/risk_scorer.py`)**
   The ML prediction serves purely as supporting evidence. Its contribution is bounded (capped at a maximum of 15 risk points) ensuring that ML alone cannot classify a benign email as malicious.

---

## 2. Model Versioning & Metadata

Every model artifact package contains metadata:

```json
{
  "artifact_version": 2,
  "model_version": "tfidf-logreg-controlled-v2",
  "classes": ["bec", "benign", "phishing", "suspicious"],
  "feature_families": ["subject_body_tfidf", "email_structure", "content_lexical"],
  "training_metadata": {
    "dataset": "ml/datasets/controlled/emails.jsonl",
    "sample_count": 32,
    "random_state": 20260907,
    "training_timestamp": "2026-09-07T...",
    "feature_version": 2,
    "metrics": {
      "accuracy": 0.75,
      "precision_macro": 0.7917,
      "recall_macro": 0.75,
      "f1_macro": 0.7417
    }
  }
}
```

---

## 3. Strict Dataset & Test Separation

The codebase enforces strict separation of concerns across datasets:

- **Training & Test Data (`ml/datasets/controlled/emails.jsonl`)**: Used exclusively by training and validation scripts (`ml/training/train.py`, `ml/training/experiments.py`).
- **Production Fixtures (`backend/tests/fixtures/emails/`)**: Consists of real RFC/MIME `.eml` emails used exclusively to verify end-to-end parser and detection engine behavior. The model is never trained on these test fixtures.
- **Evaluation Rule**: Never evaluate on training data; never report training accuracy as model generalization accuracy.

---

## 4. Explainability & Human-Readable Signals

Feature contributions are mapped to analyst-friendly descriptions:

| Feature Family | Feature Name | Description |
| :--- | :--- | :--- |
| Lexical | `has_urgency` | Suspicious urgency/action language |
| Lexical | `has_cred` | Credential/account verification language |
| Lexical | `has_financial` | Financial or payment-related language |
| Structural | `reply_to_mismatch` | Mismatched sender and Reply-To addresses |
| Structural | `html_text_ratio` | Anomalous HTML-to-text ratio |
| Structural | `url_count` / `unique_url_count` | High URL density |
| Content | TF-IDF n-grams | Content keyword matching threat profile: '...' |

---

## 5. Failure Tolerance & Fallback Behavior

If the model artifact is missing, corrupted, or incompatible:
- The classifier immediately fails-closed (`status: unavailable`, `label: unknown`, `confidence: 0.0`).
- The overall email forensic analysis pipeline proceeds uninterrupted.
- Deterministic rules, SPF/DKIM/DMARC checks, IOC extraction, and threat intelligence remain 100% active.

---

## 6. Dataset Limitations & SIH Evaluation Notice

> **Important Notice on Dataset Scale:**
> The current controlled dataset comprises 32 curated samples across four threat categories (`benign`, `phishing`, `bec`, `suspicious`). While the 75/25 stratified evaluation metrics (75.0% accuracy, 74.2% macro F1) confirm architectural correctness and pipeline integration, they should **NOT** be interpreted as production-grade accuracy on live enterprise email traffic.
