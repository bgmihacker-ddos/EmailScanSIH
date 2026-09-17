import pandas as pd
from pathlib import Path
import numpy as np

# AUDIT SCRIPT: docs/dataset/ ML robustness audit.
# Importers: pandas, pathlib, numpy
# Affected API: D:\project\email-threat-detection\docs\dataset\ CSVs
# Verbatim instruction: "P8 OBJECTIVE: Fix and properly diagnose the catastrophic LLM-phishing evaluation failure...
# STEP 2 — AUDIT ALL DATASETS... Determine the actual cause of the LLM failure."

DATA_DIR = Path("D:/project/email-threat-detection/docs/dataset")
FILES = [
    "Phishing_Email.csv",
    "phishing_legitimate_emails.csv",
    "mail_data.csv",
    "human_phishing.csv",
    "human_legit.csv",
    "llm_phishing.csv",
    "llm_legit.csv",
]

def normalize_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    return " ".join(text.split()).strip()

report = []

for fname in FILES:
    fpath = DATA_DIR / fname
    if not fpath.exists():
        report.append(f"{fname}: [NOT FOUND]")
        continue

    try:
        if fname == "llm_phishing.csv":
            df = pd.read_csv(fpath, engine="python", on_bad_lines="skip")
        else:
            df = pd.read_csv(fpath)

        # Infer labels based on train_ml.py logic
        if fname == "Phishing_Email.csv":
            labels = df["Email Type"].apply(lambda x: 1 if "phishing" in str(x).lower() else 0)
        elif fname == "phishing_legitimate_emails.csv":
            labels = df["Category"].apply(lambda x: 1 if str(x).lower() == "phishing" else 0)
        elif fname == "mail_data.csv":
            labels = pd.Series([0] * len(df)) # Explicitly benign as per train_ml.py
        elif fname in ("human_phishing.csv", "llm_phishing.csv"):
            labels = pd.Series([1] * len(df))
        else: # human_legit.csv, llm_legit.csv
            labels = pd.Series([0] * len(df))

        phish_count = labels.sum()
        benign_count = len(df) - phish_count

        report.append(f"{fname}:")
        report.append(f"  Rows: {len(df)}")
        report.append(f"  Phishing (raw label 1 count): {phish_count}")
        report.append(f"  Benign (raw label 0 count): {benign_count}")
        report.append(f"  Columns: {list(df.columns)}")

    except Exception as e:
        report.append(f"{fname}: [ERROR: {e}]")

print("\n".join(report))
