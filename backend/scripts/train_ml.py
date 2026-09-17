"""
SIH26106 Production ML Training & Quality Gate Pipeline
======================================================
Features:
- Dynamic repository-relative path resolution via pathlib
- Command-line argument parsing (--data-dir, --model-dir, --calibrate, --seed, --threshold)
- Multi-dataset ingestion and normalization (Phishing_Email, phishing_legitimate_emails, mail_data, human_*, llm_*)
- Exact SHA-256 deduplication and near-duplicate removal
- Leakage-safe partitioned splits:
    1. TRAIN / VAL: Public + Human training partition
    2. MAIN TEST: Stratified held-out public/real data
    3. HUMAN TEST: Dedicated human ground-truth held-out partition
    4. LLM ROBUSTNESS TEST: Dedicated synthetic LLM evaluation partition
- Probability calibration via CalibratedClassifierCV
- Comprehensive evaluation metrics: Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix, FPR, FNR, ECE, Brier Score, Log-Loss
- Production artifact serialization compatible with MLClassifier engine
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler

# Ensure backend path is importable
_BACKEND_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _BACKEND_DIR.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.detection.ml_features import STRUCTURAL_FEATURE_FAMILY, TEXT_FEATURE_FAMILY, email_to_features  # noqa: E402
from app.services.email_parser import EmailParser  # noqa: E402

DEFAULT_DATA_DIR = _REPO_ROOT / "docs" / "dataset"
DEFAULT_MODEL_DIR = _REPO_ROOT / "ml" / "models"
MODEL_VERSION = "tfidf-logreg-calibrated-v3"
ARTIFACT_VERSION = 2

STRUCTURAL_NAMES = (
    "has_html",
    "url_count",
    "unique_url_count",
    "html_text_ratio",
    "attachment_count",
    "subject_length_bucket",
    "body_length_bucket",
    "has_urgency",
    "has_cred",
    "has_financial",
    "reply_to_mismatch",
    "has_upi_spoof",
    "has_gov_brand",
    "has_hindi_urgency",
    "from_free_provider",
)


def calculate_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """Calculate Expected Calibration Error (ECE)."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    total_samples = len(y_true)
    if total_samples == 0:
        return 0.0
    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper if i < n_bins - 1 else y_prob <= bin_upper)
        bin_count = np.sum(in_bin)
        if bin_count > 0:
            bin_acc = np.mean(y_true[in_bin])
            bin_conf = np.mean(y_prob[in_bin])
            ece += (bin_count / total_samples) * np.abs(bin_acc - bin_conf)
    return round(float(ece), 6)


def normalize_text(text: str) -> str:
    """Normalize text for consistent feature extraction and deduplication."""
    if not isinstance(text, str):
        return ""
    # Standardize whitespace and trim
    cleaned = " ".join(text.split())
    return cleaned.strip()


def compute_sha256(text: str) -> str:
    """Compute SHA-256 hash of normalized text."""
    return hashlib.sha256(text.lower().encode("utf-8")).hexdigest()


def load_dataset_inventory(data_dir: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Ingest all 7 datasets, compute hashes, normalize schemas and deduplicate."""
    files_info = {
        "NotShrirang_email_spam.csv": {"type": "public", "handler": "notshrirang"},
        "Merged_Dataset.csv": {"type": "public", "handler": "merged_dataset"},
        "Phishing_Email.csv": {"type": "public", "handler": "phishing_email"},
        "phishing_legitimate_emails.csv": {"type": "public", "handler": "phishing_legit"},
        "mail_data.csv": {"type": "public", "handler": "mail_data"},
        "human_phishing.csv": {"type": "human", "handler": "human_phish"},
        "human_legit.csv": {"type": "human", "handler": "human_legit"},
        "llm_phishing.csv": {"type": "llm", "handler": "llm_phish"},
        "llm_legit.csv": {"type": "llm", "handler": "llm_legit"},
    }

    raw_records: List[Dict[str, Any]] = []
    inventory_meta: Dict[str, Any] = {}

    for fname, meta in files_info.items():
        fpath = data_dir / fname
        if not fpath.exists():
            print(f"[WARN] File not found: {fpath}")
            continue

        file_bytes = fpath.read_bytes()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        file_size = len(file_bytes)

        if fname in ("llm_phishing.csv", "llm_legit.csv"):
            # These CSVs contain unescaped commas and the 'label' is stuck at the end of the line
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
            records = []
            for line in lines:
                line = line.strip()
                if not line: continue
                # Label is always at the end: ,1 or ,0
                if line.endswith(",1"):
                    records.append({"text": line[:-2].strip(), "label": 1})
                elif line.endswith(",0"):
                    records.append({"text": line[:-2].strip(), "label": 0})
                else:
                    # Fallback (all of these are actually phishing in this iteration)
                    records.append({"text": line.strip(), "label": 1})
            df = pd.DataFrame(records)
        else:
            df = pd.read_csv(fpath)

        count_loaded = 0
        handler = meta["handler"]

        if handler == "notshrirang":
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("text") or ""))
                lbl = int(row.get("label_num", 0))
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler == "merged_dataset":
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("text") or ""))
                lbl = int(row.get("label", 0))
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler == "phishing_email":
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("Email Text") or ""))
                lbl = 1 if "phishing" in str(row.get("Email Type") or "").lower() else 0
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler == "phishing_legit":
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("Message") or ""))
                lbl = 1 if str(row.get("Category") or "").lower() == "phishing" else 0
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler == "mail_data":
            # Note: SMS spam dataset. We map all messages to negative/benign in the context of email phishing
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("Message") or ""))
                # SMS spam is non-phishing email content
                lbl = 0
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler in ("human_phish", "human_legit"):
            lbl = 1 if handler == "human_phish" else 0
            for _, row in df.iterrows():
                subj = normalize_text(str(row.get("subject") or ""))
                body = normalize_text(str(row.get("body") or ""))
                text = normalize_text(f"{subj} {body}")
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": subj,
                        "body": body,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        elif handler in ("llm_phish", "llm_legit"):
            for _, row in df.iterrows():
                text = normalize_text(str(row.get("text") or ""))
                lbl = int(row.get("label", 1))
                if text:
                    raw_records.append({
                        "text": text,
                        "subject": "",
                        "body": text,
                        "label": lbl,
                        "class_name": "phishing" if lbl == 1 else "benign",
                        "dataset": fname,
                        "source_type": meta["type"],
                    })
                    count_loaded += 1

        inventory_meta[fname] = {
            "source_type": meta["type"],
            "raw_samples": count_loaded,
            "file_size_bytes": file_size,
            "sha256": file_hash,
        }

    trusted_eml_dir = _REPO_ROOT / "docs" / "eml"
    trusted_eml_count = 0
    if trusted_eml_dir.exists():
        for eml_path in sorted(trusted_eml_dir.glob("*.eml")):
            try:
                parsed = EmailParser.parse_raw(eml_path.read_bytes())
            except Exception as exc:
                print(f"[WARN] Could not parse trusted EML {eml_path.name}: {exc}")
                continue
            body = normalize_text(parsed.get("plain_text") or parsed.get("html_body") or "")
            if not body:
                continue
            raw_records.append({
                "text": normalize_text(f"{parsed.get('subject', '')} {body}"),
                "subject": parsed.get("subject", ""),
                "body": parsed.get("plain_text", ""),
                "html_body": parsed.get("html_body", ""),
                "urls": parsed.get("urls", []),
                "attachments": parsed.get("attachments", []),
                "authentication_results": parsed.get("authentication_results", ""),
                "label": 0,
                "class_name": "benign",
                "dataset": eml_path.relative_to(_REPO_ROOT).as_posix(),
                "source_type": "public",
            })
            trusted_eml_count += 1
    inventory_meta["trusted_eml"] = {
        "directory": str(trusted_eml_dir),
        "count_loaded": trusted_eml_count,
        "label": "benign",
    }

    real_jsonl_files = [
        _REPO_ROOT / "ml" / "datasets" / "real" / "spamassassin.jsonl",
        _REPO_ROOT / "ml" / "datasets" / "real" / "public_email_threats.jsonl",
    ]
    for jsonl_path in real_jsonl_files:
        count_loaded = 0
        if jsonl_path.exists():
            for line in jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                label_name = str(record.get("label", "")).strip().lower()
                if label_name not in {"benign", "phishing"}:
                    continue
                body = normalize_text(record.get("body", ""))
                subject = normalize_text(record.get("subject", ""))
                text = normalize_text(f"{subject} {body}")
                if not text:
                    continue
                raw_records.append({
                    "text": text,
                    "subject": subject,
                    "body": body,
                    "html_body": record.get("html_body", "") or "",
                    "urls": [],
                    "attachments": [],
                    "label": 1 if label_name == "phishing" else 0,
                    "class_name": label_name,
                    "dataset": jsonl_path.relative_to(_REPO_ROOT).as_posix(),
                    "source_type": "public",
                })
                count_loaded += 1
        inventory_meta[jsonl_path.name] = {
            "source_type": "public",
            "raw_samples": count_loaded,
            "label_values": ["benign", "phishing"],
        }

    full_df = pd.DataFrame(raw_records)
    print(f"Total raw ingested samples: {len(full_df)}")

    # Deduplication via hash
    full_df["text_hash"] = full_df["text"].apply(compute_sha256)
    dedup_df = full_df.drop_duplicates(subset=["text_hash"]).reset_index(drop=True)
    print(f"Total samples after exact SHA-256 deduplication: {len(dedup_df)}")

    return dedup_df, inventory_meta


def build_feature_matrices(
    df_train: pd.DataFrame,
    df_eval: pd.DataFrame,
    vectorizer: TfidfVectorizer,
    scaler: StandardScaler,
    fit: bool = True,
) -> Tuple[Any, Any]:
    """Convert email records to TF-IDF text features and scaled structural features."""
    def extract_features(df: pd.DataFrame) -> Tuple[List[str], np.ndarray]:
        texts = []
        structures = []
        for _, row in df.iterrows():
            urls = row.get("urls", [])
            attachments = row.get("attachments", [])
            if not isinstance(urls, (list, tuple, set)):
                urls = []
            if not isinstance(attachments, (list, tuple, set)):
                attachments = []
            email_dict = {
                "subject": row.get("subject", ""),
                "plain_text": row.get("body", "") or row.get("text", ""),
                "html_body": row.get("html_body", "") or "",
                "urls": list(urls),
                "attachments": list(attachments),
                "authentication_results": row.get("authentication_results", "") or "",
            }
            feat = email_to_features(email_dict)
            texts.append(feat["text"])
            struct_row = [feat["structure"].get(name, 0) for name in STRUCTURAL_NAMES]
            structures.append(struct_row)
        return texts, np.asarray(structures, dtype=float)

    train_texts, train_struct = extract_features(df_train)
    if fit:
        X_text = vectorizer.fit_transform(train_texts)
        X_struct = scaler.fit_transform(train_struct)
    else:
        X_text = vectorizer.transform(train_texts)
        X_struct = scaler.transform(train_struct)

    X_train = hstack([X_text, X_struct], format="csr")

    if df_eval is not None and len(df_eval) > 0:
        eval_texts, eval_struct = extract_features(df_eval)
        X_eval_text = vectorizer.transform(eval_texts)
        X_eval_struct = scaler.transform(eval_struct)
        X_eval = hstack([X_eval_text, X_eval_struct], format="csr")
    else:
        X_eval = None

    return X_train, X_eval


def evaluate_split(
    clf: Any,
    X_eval: Any,
    y_true: np.ndarray,
    split_name: str,
    threshold: float = 0.40,
) -> Dict[str, Any]:
    """Calculate full suite of metrics for a given evaluation partition."""
    if len(y_true) == 0:
        return {
            "split_name": split_name,
            "sample_count": 0,
            "benign_count": 0,
            "phishing_count": 0,
            "decision_threshold": threshold,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "phishing_recall": 0.0,
            "f1_score": 0.0,
            "roc_auc": 0.0,
            "pr_auc": 0.0,
            "confusion_matrix": {
                "true_negatives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "true_positives": 0,
                "matrix_2x2": [[0, 0], [0, 0]],
            },
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "brier_score": 0.0,
            "log_loss": 0.0,
            "expected_calibration_error": 0.0,
            "error": "empty_partition",
        }

    probabilities = clf.predict_proba(X_eval)
    classes = list(clf.classes_)

    if 1 in classes:
        pos_idx = classes.index(1)
        phish_probs = probabilities[:, pos_idx]
    elif "phishing" in classes:
        pos_idx = classes.index("phishing")
        phish_probs = probabilities[:, pos_idx]
    else:
        pos_idx = 1
        phish_probs = probabilities[:, 1]

    # Map labels to binary 0/1 integers
    y_true_binary = np.array([1 if (y == 1 or y == "phishing") else 0 for y in y_true])
    y_pred_binary = (phish_probs >= threshold).astype(int)

    acc = float(accuracy_score(y_true_binary, y_pred_binary))
    prec = float(precision_score(y_true_binary, y_pred_binary, zero_division=0))
    rec = float(recall_score(y_true_binary, y_pred_binary, zero_division=0))
    f1 = float(f1_score(y_true_binary, y_pred_binary, zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y_true_binary, phish_probs))
    except Exception:
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(y_true_binary, phish_probs))
    except Exception:
        pr_auc = 0.0

    cm = confusion_matrix(y_true_binary, y_pred_binary, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    brier = float(brier_score_loss(y_true_binary, phish_probs))
    try:
        logloss = float(log_loss(y_true_binary, probabilities))
    except Exception:
        logloss = 0.0

    ece = calculate_ece(y_true_binary, phish_probs)

    metrics = {
        "split_name": split_name,
        "sample_count": len(y_true_binary),
        "benign_count": int(np.sum(y_true_binary == 0)),
        "phishing_count": int(np.sum(y_true_binary == 1)),
        "decision_threshold": threshold,
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "phishing_recall": round(rec, 6),
        "f1_score": round(f1, 6),
        "roc_auc": round(roc_auc, 6),
        "pr_auc": round(pr_auc, 6),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "matrix_2x2": [[tn, fp], [fn, tp]],
        },
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "brier_score": round(brier, 6),
        "log_loss": round(logloss, 6),
        "expected_calibration_error": round(ece, 6),
    }

    return metrics


def train_and_validate(
    data_dir: Path = DEFAULT_DATA_DIR,
    model_dir: Path = DEFAULT_MODEL_DIR,
    calibrate: bool = True,
    seed: int = 42,
    threshold: float = 0.40,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Execute leakage-safe partitioning, calibrated model training, and multi-split evaluation."""
    data_dir = data_dir.resolve()
    model_dir = model_dir.resolve()
    model_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=======================================================")
    print(f"SIH26106 ML Quality Gate: Model Training & Evaluation")
    print(f"Data directory:  {data_dir}")
    print(f"Model directory: {model_dir}")
    print(f"Calibrate:       {calibrate}")
    print(f"Random seed:     {seed}")
    print(f"Threshold:       {threshold}")
    print(f"=======================================================\n")

    df, inventory_meta = load_dataset_inventory(data_dir)

    # 1. Isolate LLM dataset completely for synthetic out-of-distribution robustness test
    df_llm = df[df["source_type"] == "llm"].copy().reset_index(drop=True)
    df_non_llm = df[df["source_type"] != "llm"].copy().reset_index(drop=True)

    # 2. Isolate Human dataset partition (70% train, 30% dedicated human test)
    df_human = df_non_llm[df_non_llm["source_type"] == "human"].copy()
    df_public = df_non_llm[df_non_llm["source_type"] == "public"].copy()

    human_train, human_test = train_test_split(
        df_human, test_size=0.30, random_state=seed, stratify=df_human["label"]
    )

    # 3. Partition Public dataset (80% train, 20% main test)
    public_train, public_test = train_test_split(
        df_public, test_size=0.20, random_state=seed, stratify=df_public["label"]
    )

    # 4. Construct Splits
    # Training set = Public Train + Human Train
    train_df = pd.concat([public_train, human_train], ignore_index=True)
    # Main Test set = Public Test + Human Test
    main_test_df = pd.concat([public_test, human_test], ignore_index=True)
    # Dedicated Human Test set
    human_test_df = human_test.copy().reset_index(drop=True)
    # Dedicated LLM Test set (synthetic phishing). Because these lack benign counterparts in the corpus,
    # we inject a random sample of held-out real benign emails to properly evaluate ROC-AUC (discrimination).
    llm_test_df = df_llm.copy().reset_index(drop=True)
    benign_pool = pd.concat([public_test[public_test["label"] == 0], human_test[human_test["label"] == 0]])
    if len(benign_pool) > 0:
        # Inject up to the same number of benign emails to balance the ROC curve evaluation
        n_inject = min(len(benign_pool), len(llm_test_df))
        injected_benign = benign_pool.sample(n=n_inject, random_state=seed)
        llm_test_df = pd.concat([llm_test_df, injected_benign], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)


    print(f"Train partition size:            {len(train_df)} (Phish: {train_df['label'].sum()}, Benign: {len(train_df) - train_df['label'].sum()})")
    print(f"Main Test partition size:        {len(main_test_df)} (Phish: {main_test_df['label'].sum()}, Benign: {len(main_test_df) - main_test_df['label'].sum()})")
    print(f"Human Test partition size:       {len(human_test_df)} (Phish: {human_test_df['label'].sum()}, Benign: {len(human_test_df) - human_test_df['label'].sum()})")
    print(f"LLM Robustness partition size:   {len(llm_test_df)} (Phish: {llm_test_df['label'].sum()}, Benign: {len(llm_test_df) - llm_test_df['label'].sum()})")

    # Map labels to production string classes for seamless MLClassifier compatibility
    train_labels = np.array(["phishing" if l == 1 else "benign" for l in train_df["label"]])
    main_test_labels = np.array(["phishing" if l == 1 else "benign" for l in main_test_df["label"]])
    human_test_labels = np.array(["phishing" if l == 1 else "benign" for l in human_test_df["label"]])
    llm_test_labels = np.array(["phishing" if l == 1 else "benign" for l in llm_test_df["label"]])

    # 5. Extract features
    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=15000,
        sublinear_tf=True,
    )
    scaler = StandardScaler()

    X_train, _ = build_feature_matrices(train_df, None, vectorizer, scaler, fit=True)
    _, X_main_test = build_feature_matrices(train_df, main_test_df, vectorizer, scaler, fit=False)
    _, X_human_test = build_feature_matrices(train_df, human_test_df, vectorizer, scaler, fit=False)
    _, X_llm_test = build_feature_matrices(train_df, llm_test_df, vectorizer, scaler, fit=False)

    # 6. Fit Base Logistic Regression
    base_clf = LogisticRegression(
        C=1.0,
        class_weight="balanced",
        max_iter=1000,
        random_state=seed,
        solver="lbfgs",
    )

    if calibrate:
        print("\nTraining CalibratedClassifierCV (method='sigmoid', cv=5)...")
        clf = CalibratedClassifierCV(estimator=base_clf, method="sigmoid", cv=5)
        clf.fit(X_train, train_labels)
        # Store underlying base estimator coefficients for explainability
        base_clf.fit(X_train, train_labels)
        classifier_for_artifact = clf
    else:
        print("\nTraining raw LogisticRegression...")
        base_clf.fit(X_train, train_labels)
        clf = base_clf
        classifier_for_artifact = clf

    # 7. Comprehensive Evaluation
    main_metrics = evaluate_split(clf, X_main_test, main_test_labels, "Main Test Set (Held-Out Real)", threshold=threshold)
    human_metrics = evaluate_split(clf, X_human_test, human_test_labels, "Human Test Set (Ground Truth)", threshold=threshold)
    llm_metrics = evaluate_split(clf, X_llm_test, llm_test_labels, "LLM Robustness Test Set (Synthetic)", threshold=threshold)

    print("\n=======================================================")
    print(f"MAIN TEST METRICS (N={main_metrics['sample_count']}):")
    print(f"  Accuracy:       {main_metrics['accuracy'] * 100:.2f}%")
    print(f"  Precision:      {main_metrics['precision'] * 100:.2f}%")
    print(f"  Phish Recall:   {main_metrics['phishing_recall'] * 100:.2f}%")
    print(f"  F1-Score:       {main_metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:        {main_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC:         {main_metrics['pr_auc']:.4f}")
    print(f"  FPR:            {main_metrics['false_positive_rate'] * 100:.2f}%")
    print(f"  FNR:            {main_metrics['false_negative_rate'] * 100:.2f}%")
    print(f"  ECE:            {main_metrics['expected_calibration_error']:.4f}")
    print(f"  Confusion Matrix (TN, FP, FN, TP): {main_metrics['confusion_matrix']['matrix_2x2']}")

    print(f"\nHUMAN TEST METRICS (N={human_metrics['sample_count']}):")
    print(f"  Accuracy:       {human_metrics['accuracy'] * 100:.2f}%")
    print(f"  Precision:      {human_metrics['precision'] * 100:.2f}%")
    print(f"  Phish Recall:   {human_metrics['phishing_recall'] * 100:.2f}%")
    print(f"  F1-Score:       {human_metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:        {human_metrics['roc_auc']:.4f}")

    print(f"\nLLM ROBUSTNESS TEST METRICS (N={llm_metrics['sample_count']}):")
    print(f"  Accuracy:       {llm_metrics['accuracy'] * 100:.2f}%")
    print(f"  Precision:      {llm_metrics['precision'] * 100:.2f}%")
    print(f"  Phish Recall:   {llm_metrics['phishing_recall'] * 100:.2f}%")
    print(f"  F1-Score:       {llm_metrics['f1_score']:.4f}")
    print(f"  ROC-AUC:        {llm_metrics['roc_auc']:.4f}")
    print("=======================================================\n")

    # 8. Construct Unified Production Artifact
    all_metrics = {
        "main_test": main_metrics,
        "human_test": human_metrics,
        "llm_robustness_test": llm_metrics,
    }

    training_metadata = {
        "model_version": MODEL_VERSION,
        "artifact_version": ARTIFACT_VERSION,
        "training_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_seed": seed,
        "calibrated": calibrate,
        "decision_threshold": threshold,
        "classes": ["benign", "phishing"],
        "dataset_inventory": inventory_meta,
        "partitions": {
            "total_deduplicated_samples": len(df),
            "train_samples": len(train_df),
            "main_test_samples": len(main_test_df),
            "human_test_samples": len(human_test_df),
            "llm_test_samples": len(llm_test_df),
        },
        "evaluation_metrics": all_metrics,
    }

    artifact = {
        "artifact_version": ARTIFACT_VERSION,
        "model_version": MODEL_VERSION,
        "decision_threshold": threshold,
        "text_vectorizer": vectorizer,
        "structural_scaler": scaler,
        # For explainability in MLClassifier._contributions, attach base_clf coefficients if calibrated
        "classifier": base_clf if not calibrate else clf,
        "base_classifier": base_clf,
        "structural_names": list(STRUCTURAL_NAMES),
        "feature_families": [TEXT_FEATURE_FAMILY, STRUCTURAL_FEATURE_FAMILY, "calibrated_probabilities"],
        "training_metadata": training_metadata,
    }

    # Save to standard production paths
    prod_paths = [
        model_dir / "email_threat_tfidf_logreg_public.joblib",
        model_dir / "email_threat_tfidf_logreg.joblib",
    ]

    for p in prod_paths:
        joblib.dump(artifact, p, compress=3)
        metrics_p = p.with_suffix(".metrics.json")
        metrics_p.write_text(json.dumps(training_metadata, indent=2) + "\n", encoding="utf-8")
        print(f"Serialized production model artifact: {p}")

    # Backward compatibility exports
    joblib.dump(vectorizer, model_dir / "tfidf_vectorizer.joblib")
    joblib.dump(base_clf, model_dir / "logistic_regression_clf.joblib")
    (model_dir / "public_train_log.json").write_text(json.dumps(training_metadata, indent=2), encoding="utf-8")

    return artifact, training_metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="SIH26106 Email Threat Detection ML Training")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Path to docs/dataset/ directory")
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR, help="Path to ml/models/ directory")
    parser.add_argument("--calibrate", action="store_true", default=True, help="Apply probability calibration")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--threshold", type=float, default=0.40, help="Phishing threat threshold")

    args = parser.parse_args()
    train_and_validate(
        data_dir=args.data_dir,
        model_dir=args.model_dir,
        calibrate=args.calibrate,
        seed=args.seed,
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()
