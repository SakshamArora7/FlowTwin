import math

import numpy as np
import pytest

from backend.app.detection import load_model, local_contributions, model_metrics, predict
from ml.schema import FEATURES, SCHEMA_VERSION


def test_installed_model_feature_schema_and_local_explanation():
    artifact = load_model()
    if artifact is None:
        pytest.skip("No trained CIC-IDS2017 model artifact installed")
    assert artifact["schema_version"] == SCHEMA_VERSION
    assert artifact["features"] == list(FEATURES)
    metrics = model_metrics()
    assert set(metrics["classes"]) == set(artifact["pipeline"].classes_)
    assert metrics["train_rows"] > 0 and metrics["test_rows"] > 0
    features = dict(zip(FEATURES, (200_000.0, 3, 2, 0, 2, 0, 2)))
    predicted = predict(features)
    assert predicted["category"] in metrics["classes"]
    assert 0 <= predicted["confidence"] <= 1
    assert predicted["explanation"] and all(x["feature"] in FEATURES for x in predicted["explanation"])
    pipeline = artifact["pipeline"]
    forest = pipeline.named_steps["forest"]
    row = pipeline.named_steps["imputer"].transform([[features[k] for k in FEATURES]])[0]
    winner = list(forest.classes_).index(predicted["category"])
    baseline, contributions = local_contributions(forest, row, winner)
    assert math.isclose(baseline + sum(contributions), predicted["confidence"], abs_tol=0.0001)


def test_feature_order_is_rejected_when_a_required_feature_is_missing():
    artifact = load_model()
    if artifact is None:
        pytest.skip("No model installed")
    with pytest.raises(ValueError, match="missing required model features"):
        predict({"Flow Duration": 1.0})
