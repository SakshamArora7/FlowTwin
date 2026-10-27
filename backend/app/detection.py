"""Model inference and path-based local contributions for a Random Forest."""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.schema import FEATURES, SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[2] / "ml" / "artifacts"


_cache = {"modified": None, "artifact": None}


def load_model():
    path = ROOT / "model.joblib"
    if not path.exists():
        return None
    modified = path.stat().st_mtime_ns
    if _cache["modified"] == modified:
        return _cache["artifact"]
    artifact = joblib.load(path)
    if artifact.get("schema_version") != SCHEMA_VERSION or artifact.get("features") != list(FEATURES):
        raise RuntimeError("Model feature schema does not match the packet extractor")
    _cache.update(modified=modified, artifact=artifact)
    return artifact


def model_metrics():
    path = ROOT / "metrics.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def local_contributions(forest, row, class_index):
    """Mean per-feature change in class probability along each tree decision path."""
    contributions = np.zeros(len(FEATURES), dtype=float)
    base = 0.0
    for tree in forest.estimators_:
        nodes = tree.tree_
        current = 0
        parent = nodes.value[current][0]
        base += parent[class_index] / parent.sum()
        while nodes.children_left[current] != nodes.children_right[current]:
            feature = nodes.feature[current]
            child = nodes.children_left[current] if row[feature] <= nodes.threshold[current] else nodes.children_right[current]
            before = nodes.value[current][0]
            after = nodes.value[child][0]
            contributions[feature] += after[class_index] / after.sum() - before[class_index] / before.sum()
            current = child
    return base / len(forest.estimators_), (contributions / len(forest.estimators_)).tolist()


def predict(features):
    artifact = load_model()
    if artifact is None:
        return None
    if set(FEATURES) - set(features):
        raise ValueError("Flow is missing required model features")
    frame = pd.DataFrame([{name: features[name] for name in FEATURES}], columns=FEATURES)
    pipeline = artifact["pipeline"]
    probability = pipeline.predict_proba(frame)[0]
    forest = pipeline.named_steps["forest"]
    winner = int(np.argmax(probability))
    category = str(forest.classes_[winner])
    transformed = pipeline.named_steps["imputer"].transform(frame)[0]
    baseline, contributions = local_contributions(forest, transformed, winner)
    explanation = sorted(({
        "feature": name, "value": float(features[name]), "contribution": round(value, 5),
        "description": f"This feature changed the forest's {category} vote by {value:+.1%} relative to the average root vote."
    } for name, value in zip(FEATURES, contributions)), key=lambda item: abs(item["contribution"]), reverse=True)[:5]
    return {
        "category": category, "confidence": round(float(probability[winner]), 4),
        "severity": "Low" if category == "Benign" else "High" if float(probability[winner]) >= 0.8 else "Medium",
        "model_version": SCHEMA_VERSION, "explanation": explanation,
        "baseline_probability": round(baseline, 4),
    }
