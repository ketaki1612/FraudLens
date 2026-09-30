"""
Trains an Isolation Forest on training_data.csv and saves the
trained model (plus normalization info) to fraud_model.pkl.

Run this ONCE (or whenever you regenerate training_data.csv / want
to retrain). ml_scoring.py loads the saved file at API startup -
it does NOT retrain on every request.

Usage:
    python train_model.py
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

INPUT_FILE = "training_data.csv"
MODEL_FILE = "fraud_model.pkl"

FEATURES = ["amount_gbp", "hour_of_day", "channel_encoded", "is_risky_location"]


def main():
    df = pd.read_csv(INPUT_FILE)
    X = df[FEATURES]

    # contamination = expected proportion of anomalies in the data.
    # We seeded ~4% anomalies in generate_training_data.py, so this matches.
    model = IsolationForest(contamination=0.04, random_state=42, n_estimators=200)
    model.fit(X)

    # decision_function: higher = more "normal", lower (often negative) = more anomalous.
    # We save the min/max from training so ml_scoring.py can convert any future
    # transaction's raw score into a consistent 0-100 risk scale.
    scores = model.decision_function(X)
    score_min = float(scores.min())
    score_max = float(scores.max())

    joblib.dump(
        {"model": model, "score_min": score_min, "score_max": score_max, "features": FEATURES},
        MODEL_FILE,
    )

    print(f"Trained on {len(df)} rows.")
    print(f"Saved model to {MODEL_FILE}")
    print(f"Training score range: min={score_min:.4f}, max={score_max:.4f}")


if __name__ == "__main__":
    main()