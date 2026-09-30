"""
Rule engine for fraud detection.

Rules are now stored in tblFraudRules (DB), not hardcoded as Python
functions - so an Admin can create/edit/delete rules from the
frontend without any code changes or redeployment.

Each rule has a ConditionType (what KIND of check it performs) and
a ParametersJson (the specific values for that check, e.g. a
threshold amount or a list of countries). CONDITION_HANDLERS below
maps each ConditionType to a small generic function that knows how
to evaluate that kind of condition using whatever parameters it's
given - adding a brand new rule of an EXISTING condition type never
needs new code, only a new database row.

CURRENCY HANDLING:
Every amount is converted to GBP first (see RATE_TO_GBP), then rule
thresholds (in ParametersJson, always as "threshold_gbp") are
applied - so a rule means the same real-world value no matter what
currency the transaction came in as. Rates are approximate/static,
not live - fine for a portfolio project.
"""

import json
from datetime import datetime

from db import get_connection

RISKY_COUNTRIES = ["Iran", "Afghanistan", "Brazil"]  # still used by ml_scoring.py

# Approximate value of 1 unit of each currency, in GBP.
RATE_TO_GBP = {
    "GBP": 1.0,
    "USD": 0.79,   "EUR": 0.85,   "JPY": 0.0053, "CNY": 0.11,
    "INR": 0.0095, "AUD": 0.52,   "CAD": 0.58,   "CHF": 0.90,
    "HKD": 0.10,   "SGD": 0.59,   "SEK": 0.075,  "NOK": 0.073,
    "DKK": 0.114,  "NZD": 0.48,   "ZAR": 0.043,  "AED": 0.215,
    "SAR": 0.21,   "BRL": 0.145,  "MXN": 0.046,  "RUB": 0.0086,
    "KRW": 0.00058,"TRY": 0.023,  "PLN": 0.20,   "THB": 0.023,
    "IDR": 0.00005,"MYR": 0.168,  "PHP": 0.0136, "VND": 0.000031,
    "EGP": 0.016,  "NGN": 0.00052,"PKR": 0.0028, "BDT": 0.0067,
    "ILS": 0.21,   "CZK": 0.034,  "HUF": 0.0021, "RON": 0.171,
    "ARS": 0.00082,"CLP": 0.00083,"COP": 0.00019,"KES": 0.0061,
}


def get_gbp_amount(amount: float, currency_code: str) -> float:
    """Converts an amount into its GBP equivalent. Falls back to rate=1.0 if unknown."""
    rate = RATE_TO_GBP.get(currency_code, 1.0)
    return amount * rate


def _get_txn_hour(txn: dict) -> int:
    txn_time = txn["transaction_date_time"]
    if isinstance(txn_time, str):
        txn_time = datetime.fromisoformat(txn_time)
    return txn_time.hour


# --- Condition handlers -----------------------------------------------
# Each takes (txn, params) and returns True/False.

def check_amount_gte_and_location_in(txn: dict, params: dict) -> bool:
    gbp_amount = get_gbp_amount(txn["amount"], txn["currency_code"])
    if gbp_amount < params["threshold_gbp"]:
        return False
    location = (txn["location"] or "").lower()
    return any(loc.lower() in location for loc in params["locations"])


def check_amount_gte(txn: dict, params: dict) -> bool:
    gbp_amount = get_gbp_amount(txn["amount"], txn["currency_code"])
    return gbp_amount >= params["threshold_gbp"]


def check_channel_eq_and_amount_lte(txn: dict, params: dict) -> bool:
    gbp_amount = get_gbp_amount(txn["amount"], txn["currency_code"])
    return txn["channel"] == params["channel"] and gbp_amount <= params["threshold_gbp"]


def check_channel_eq_and_amount_gte(txn: dict, params: dict) -> bool:
    gbp_amount = get_gbp_amount(txn["amount"], txn["currency_code"])
    return txn["channel"] == params["channel"] and gbp_amount >= params["threshold_gbp"]


def check_hour_range(txn: dict, params: dict) -> bool:
    hour = _get_txn_hour(txn)
    return params["start_hour"] <= hour < params["end_hour"]


def check_missing_desc_and_amount_gte(txn: dict, params: dict) -> bool:
    gbp_amount = get_gbp_amount(txn["amount"], txn["currency_code"])
    return not txn.get("item_description") and gbp_amount >= params["threshold_gbp"]


CONDITION_HANDLERS = {
    "AMOUNT_GTE_AND_LOCATION_IN": check_amount_gte_and_location_in,
    "AMOUNT_GTE": check_amount_gte,
    "CHANNEL_EQ_AND_AMOUNT_LTE": check_channel_eq_and_amount_lte,
    "CHANNEL_EQ_AND_AMOUNT_GTE": check_channel_eq_and_amount_gte,
    "HOUR_RANGE": check_hour_range,
    "MISSING_DESC_AND_AMOUNT_GTE": check_missing_desc_and_amount_gte,
}


def fetch_active_rules() -> list:
    """Fetches all active rules from tblFraudRules."""
    query = """
        SELECT RuleId, RuleKey, RuleName, Description, ConditionType,
               ParametersJson, Points, IsActive
        FROM dbo.tblFraudRules
        WHERE IsActive = 1
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

    return [
        {
            "rule_id": row.RuleId,
            "rule_key": row.RuleKey,
            "rule_name": row.RuleName,
            "description": row.Description,
            "condition_type": row.ConditionType,
            "parameters": json.loads(row.ParametersJson),
            "points": float(row.Points),
        }
        for row in rows
    ]


def evaluate_rules(txn: dict) -> tuple[bool, str, float]:
    """
    Fetches active rules from the DB, evaluates each against the
    transaction, sums points from any that trigger, and maps the
    total to a status.

    Returns (is_risky, status, risk_score). Note: main.py recomputes
    its own final status after blending in the ML score - the status
    returned here reflects rules alone.

    txn is expected to have keys: amount, currency_code, location,
    channel, item_description, transaction_date_time.
    """
    total_score = 0.0

    for rule in fetch_active_rules():
        handler = CONDITION_HANDLERS.get(rule["condition_type"])
        if handler is None:
            continue  # unknown condition type - skip rather than crash
        if handler(txn, rule["parameters"]):
            total_score += rule["points"]

    total_score = min(total_score, 100.0)

    if total_score >= 70:
        status = "Rejected"
    elif total_score >= 20:
        status = "Flagged"
    else:
        status = "Approved"

    is_risky = total_score >= 20
    return is_risky, status, total_score