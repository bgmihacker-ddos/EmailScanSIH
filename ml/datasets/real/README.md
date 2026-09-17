# Real email corpus imports

This directory contains generated datasets imported from public, labeled corpora. Raw archives are not committed.

## SpamAssassin public corpus

Source: https://spamassassin.apache.org/old/publiccorpus/

The importer maps `easy_ham` and `hard_ham` to `benign`, and `spam` to `phishing` for a binary baseline. This corpus is useful for spam/ham quality and feature-contract testing, but it is not representative of BEC, malware attachments, or modern enterprise traffic. Do not report this dataset's metrics as broad phishing or fraud accuracy.

Import command:

```powershell
python ml/training/import_spamassassin.py --input-dir <extracted-corpus> --output ml/datasets/real/spamassassin.jsonl
```

## Mixed public corpus

`public_email_threats.jsonl` combines SpamAssassin with benign Enron enterprise mail. The Enron importer reads the original `.tgz` directly on Windows when extracted Maildir filenames end in a trailing dot. The current generated corpus contains 3,250 records: 1,852 benign and 1,398 phishing.

Train the explainable model with:

```powershell
python ml/training/train.py --dataset ml/datasets/real/public_email_threats.jsonl --artifact ml/models/email_threat_tfidf_logreg_public.joblib
```

Metrics are held-out corpus metrics, not a guarantee of current-world phishing, BEC, malware, or business-fraud performance. The model uses grouped source-aware evaluation when duplicate source identifiers exist.
