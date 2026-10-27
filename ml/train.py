"""Train a real Random Forest using selected CIC-IDS2017 Parquet flow tables.

Use: python -m ml.train --data datasets/raw --output ml/artifacts
"""
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

from .schema import FEATURES, SCHEMA_VERSION, normalize_label


def read_files(folder, max_rows_per_class=12000):
    paths = sorted(Path(folder).glob("*.parquet")) + sorted(Path(folder).glob("*.csv"))
    if not paths:
        raise ValueError("No CIC-IDS2017 Parquet or CSV files found. Run datasets/fetch_cicids2017.py first.")
    frames = []
    provenance = []
    for path in paths:
        frame = pd.read_parquet(path, columns=[*FEATURES, "Label"]) if path.suffix == ".parquet" else pd.read_csv(path, usecols=lambda name: name.strip() in {*FEATURES, "Label"}, low_memory=False)
        frame.columns = [str(name).strip() for name in frame.columns]
        missing = set(FEATURES) - set(frame.columns)
        if missing or "Label" not in frame:
            raise ValueError(f"{path.name} lacks expected columns: {sorted(missing | ({'Label'} if 'Label' not in frame else set()))}")
        frame["class"] = frame["Label"].map(normalize_label)
        frame = frame.loc[frame["class"].notna(), [*FEATURES, "class"]].copy()
        for feature in FEATURES:
            frame[feature] = pd.to_numeric(frame[feature], errors="coerce")
        frame.replace([np.inf, -np.inf], np.nan, inplace=True)
        frame = frame.loc[frame[list(FEATURES)].notna().sum(axis=1) >= 5]
        frame = frame.drop_duplicates(subset=[*FEATURES, "class"], keep="first")
        frame["file"] = path.name
        frame["order"] = np.arange(len(frame))
        frames.append(frame)
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        provenance.append({"file": path.name, "sha256": digest, "usable_rows": len(frame)})
    data = pd.concat(frames, ignore_index=True)
    if data["class"].nunique() < 2:
        raise ValueError("At least two supported classes are required for training.")
    # Preserve original order within each source file and class for a later-record holdout.
    train_parts, test_parts = [], []
    for (_, _), group in data.groupby(["file", "class"], sort=False):
        if len(group) < 30:
            continue
        cut = max(1, int(len(group) * 0.8))
        train_parts.append(group.iloc[:cut].tail(max_rows_per_class))
        test_parts.append(group.iloc[cut:].head(max(100, max_rows_per_class // 4)))
    train = pd.concat(train_parts, ignore_index=True)
    test = pd.concat(test_parts, ignore_index=True)
    classes = sorted(set(train["class"]) & set(test["class"]))
    train, test = train[train["class"].isin(classes)], test[test["class"].isin(classes)]
    # Remove identical feature vectors from test, even when labels differ.
    train_keys = pd.util.hash_pandas_object(train[list(FEATURES)], index=False)
    test_keys = pd.util.hash_pandas_object(test[list(FEATURES)], index=False)
    test = test.loc[~test_keys.isin(set(train_keys))]
    if len(test) < 100 or len(classes) < 2:
        raise ValueError("Not enough distinct later records for evaluation.")
    return train, test, classes, provenance


def train_model(data, output, max_rows_per_class=12000):
    train, test, classes, provenance = read_files(data, max_rows_per_class)
    x_train, x_test = train[list(FEATURES)], test[list(FEATURES)]
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("forest", RandomForestClassifier(n_estimators=120, min_samples_leaf=3, max_features="sqrt", class_weight="balanced_subsample", n_jobs=-1, random_state=42)),
    ])
    model.fit(x_train, train["class"])
    predicted = model.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(test["class"], predicted, labels=classes, average="weighted", zero_division=0)
    result = {
        "trained_at": datetime.now(timezone.utc).isoformat(), "schema_version": SCHEMA_VERSION,
        "features": list(FEATURES), "classes": classes,
        "train_rows": len(train), "test_rows": len(test),
        "train_class_counts": dict(Counter(train["class"])), "test_class_counts": dict(Counter(test["class"])),
        "accuracy": accuracy_score(test["class"], predicted), "precision_weighted": precision,
        "recall_weighted": recall, "f1_weighted": f1,
        "per_class": classification_report(test["class"], predicted, labels=classes, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(test["class"], predicted, labels=classes).tolist(),
        "feature_importance": dict(zip(FEATURES, model.named_steps["forest"].feature_importances_.tolist())),
        "sources": provenance,
        "evaluation_note": "Later-row holdout within each source file and class; duplicate feature vectors removed across train/test. This is not a held-out capture/day, and traffic from the same scenarios may remain correlated. Sampling caps class sizes and changes prevalence. Scores measure this corpus only, not real-world detection quality or PCAP-extractor equivalence.",
    }
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": model, "features": list(FEATURES), "schema_version": SCHEMA_VERSION}, out / "model.joblib")
    (out / "metrics.json").write_text(json.dumps(result, indent=2, default=float), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="datasets/raw")
    parser.add_argument("--output", default="ml/artifacts")
    parser.add_argument("--max-rows-per-class", type=int, default=12000)
    args = parser.parse_args()
    result = train_model(args.data, args.output, args.max_rows_per_class)
    print(json.dumps({k: result[k] for k in ("classes", "train_rows", "test_rows", "accuracy", "precision_weighted", "recall_weighted", "f1_weighted")}, indent=2))


if __name__ == "__main__":
    main()
