# Controlled ML training data

This directory contains a small, sanitized, hand-authored corpus used only to
exercise the local TF-IDF + logistic-regression training and evaluation code.
It is **not production email data**, is not representative of field traffic,
and must not be presented as an accuracy claim. The API, dashboard, persistence
layer, and test fixture validation do not read this directory at runtime.

The records contain short message-like text and structural metadata. They do not
contain credentials, live payloads, API keys, or personal data. Add a larger,
consented, independently labelled corpus before using this model for operational
 decisions.
