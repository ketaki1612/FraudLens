"""
Generates a synthetic training dataset for the Isolation Forest model
and saves it as training_data.csv.

Unlike generate_sample_data.py (which POSTs to your live API so
transactions go through the rule engine and land in your real DB),
this script writes STRAIGHT TO A CSV, bypassing the API entirely.
That's much faster for generating thousands of rows purely for
model training, and keeps your actual transaction table clean of
pure-training noise.

The ML model needs NUMERIC features, so this script also does the
feature engineering (converting raw fields into numbers) as it goes.

Usage:
    python generate_training_data.py
"""

import csv
import random
from datetime import datetime, timedelta

ROWS = 2000
OUTPUT_FILE = "training_data.csv"

# Same GBP conversion approach as rules.py, kept simple/duplicated here
# so this script has no dependency on the API being importable.
RATE_TO_GBP = {
    "GBP": 1.0, "USD": 0.79, "EUR": 0.85, "INR": 0.0095,
    "JPY": 0.0053, "AUD": 0.52, "CAD": 0.58,
}

CHANNELS = ["card_present", "ecom", "mobile", "atm"]
CHANNEL_TO_NUM = {c: i for i, c in enumerate(CHANNELS)}

NORMAL_LOCATIONS = ["London, UK", "Manchester, UK", "Birmingham, UK", "Leeds, UK", "Paris, France", "New York, US"]
RISKY_LOCATIONS = ["Tehran, Iran", "Kabul, Afghanistan", "Sao Paulo, Brazil"]


def random_normal_transaction():
    """The vast majority of rows: everyday, unremarkable transactions."""
    currency = random.choices(list(RATE_TO_GBP.keys()), weights=[50, 20, 15, 10, 2, 2, 1], k=1)[0]
    amount = round(random.uniform(5, 400), 2)
    hour = random.choices(range(24), weights=[2 if h in (1, 2, 3) else 10 for h in range(24)], k=1)[0]
    channel = random.choice(CHANNELS)
    location = random.choice(NORMAL_LOCATIONS)
    return amount, currency, hour, channel, location


def random_anomalous_transaction():
    """
    A small minority: genuinely unusual combinations, for the model
    to eventually learn to recognise as "different from the rest".
    Isolation Forest doesn't need these labeled - it works purely
    unsupervised - but seeding some real outliers makes sure there's
    something for it to actually find.
    """
    pattern = random.choice(["huge_amount", "odd_hour_risky", "tiny_repeated", "atm_spike"])
    currency = "GBP"

    if pattern == "huge_amount":
        amount = round(random.uniform(3000, 10000), 2)
        hour = random.randint(9, 20)
        channel = random.choice(CHANNELS)
        location = random.choice(NORMAL_LOCATIONS)
    elif pattern == "odd_hour_risky":
        amount = round(random.uniform(400, 1500), 2)
        hour = random.randint(1, 4)
        channel = "ecom"
        location = random.choice(RISKY_LOCATIONS)
    elif pattern == "tiny_repeated":
        amount = round(random.uniform(0.5, 2), 2)
        hour = random.randint(0, 23)
        channel = "ecom"
        location = random.choice(NORMAL_LOCATIONS)
    else:  # atm_spike
        amount = round(random.uniform(800, 2000), 2)
        hour = random.randint(0, 23)
        channel = "atm"
        location = random.choice(NORMAL_LOCATIONS)

    return amount, currency, hour, channel, location


def build_row(amount, currency, hour, channel, location):
    """Converts raw values into the numeric feature row the model needs."""
    amount_gbp = round(amount * RATE_TO_GBP.get(currency, 1.0), 2)
    is_risky_location = 1 if any(c.split(",")[-1].strip().lower() in location.lower()
                                  for c in RISKY_LOCATIONS) else 0
    return {
        "amount_gbp": amount_gbp,
        "hour_of_day": hour,
        "channel_encoded": CHANNEL_TO_NUM[channel],
        "is_risky_location": is_risky_location,
    }


def main():
    anomaly_count = int(ROWS * 0.04)  # ~4% seeded anomalies
    normal_count = ROWS - anomaly_count

    rows = []
    for _ in range(normal_count):
        rows.append(build_row(*random_normal_transaction()))
    for _ in range(anomaly_count):
        rows.append(build_row(*random_anomalous_transaction()))

    random.shuffle(rows)

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["amount_gbp", "hour_of_day", "channel_encoded", "is_risky_location"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT_FILE} ({normal_count} normal, {anomaly_count} seeded anomalies)")


if __name__ == "__main__":
    main()