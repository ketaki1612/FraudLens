"""
Loads the trained Isolation Forest (fraud_model.pkl) once at import
time, and exposes get_ml_score(txn) -> float (0-100) for main.py to
call alongside the rule engine.

Reuses RATE_TO_GBP and RISKY_COUNTRIES from rules.py so the feature
engineering here exactly matches what generate_training_data.py used
to build the training set - the model must see features built the
same way it was trained on, or its scores won't mean anything.
"""

import os
from datetime import datetime

import joblib
import pandas as pd

from rules import RATE_TO_GBP, RISKY_COUNTRIES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "fraud_model.pkl")

CHANNELS = ["card_present", "ecom", "mobile", "atm"]
CHANNEL_TO_NUM = {c: i for i, c in enumerate(CHANNELS)}

_bundle = None  # loaded lazily so the API can still start even if the model isn't trained yet


def _load_bundle():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"{MODEL_PATH} not found. Run train_model.py first to create it."
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def _build_features(txn: dict) -> list:
    """Converts a transaction dict into the same 4 numeric features used in training."""
    amount_gbp = txn["amount"] * RATE_TO_GBP.get(txn["currency_code"], 1.0)

    txn_time = txn["transaction_date_time"]
    if isinstance(txn_time, str):
        txn_time = datetime.fromisoformat(txn_time)
    hour_of_day = txn_time.hour

    channel_encoded = CHANNEL_TO_NUM.get(txn["channel"], 0)

    location = (txn["location"] or "").lower()
    is_risky_location = 1 if any(c.lower() in location for c in RISKY_COUNTRIES) else 0

    return [amount_gbp, hour_of_day, channel_encoded, is_risky_location]


def get_ml_score(txn: dict) -> float:
    """
    Returns an anomaly score from 0 (looks normal) to 100 (looks very
    anomalous) for a transaction, using the trained Isolation Forest.
    """
    bundle = _load_bundle()
    model = bundle["model"]
    score_min = bundle["score_min"]
    score_max = bundle["score_max"]

    features = pd.DataFrame([_build_features(txn)], columns=bundle["features"])
    raw_score = model.decision_function(features)[0]

    # Flip and normalize: raw_score near score_max -> 0 risk, near score_min -> 100 risk.
    if score_max == score_min:
        return 0.0
    normalized = (score_max - raw_score) / (score_max - score_min) * 100
    return round(max(0.0, min(100.0, normalized)), 2)