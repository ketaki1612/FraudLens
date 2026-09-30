"""
Seeds sample tblAuditLog entries for the users created by test_users.py.

There's no API endpoint for writing audit logs yet (that wiring - where
every action automatically logs itself - is a future step), so this
script inserts directly into the database via db.py's connection,
using plausible actions per role.

Usage:
    Run AFTER test_users.py, from inside the api folder (venv active):
        python seed_audit_logs.py
"""

import random
from datetime import datetime, timedelta

from db import get_connection

# Plausible actions per role, matching what each role can actually do
# per the Settings page's Role Permissions.
ADMIN_ACTIONS = [
    "Fraud Rules > Created rule: card_testing_pattern",
    "Fraud Rules > Updated rule: high_amount_risky_country.threshold_gbp",
    "Fraud Rules > Deleted rule: test_rule_temp",
    "Settings > Created user: priya.sharma",
    "Settings > Deactivated user: sofia.rossi",
]
ANALYST_ACTIONS = [
    "Dashboard > Viewed",
    "Transactions > Viewed transaction list",
    "Transactions > Filtered by status: Flagged",
    "Fraud Rules > Viewed (read-only)",
]
AUDITOR_ACTIONS = [
    "Audit Logs > Viewed",
    "Transactions > Viewed transaction list",
    "Fraud Rules > Viewed (read-only)",
    "Dashboard > Viewed",
]

SAMPLE_IPS = ["192.168.1.42", "10.0.0.15", "172.16.0.8", "203.0.113.27"]

ACTIONS_BY_ROLE = {"Admin": ADMIN_ACTIONS, "Analyst": ANALYST_ACTIONS, "Auditor": AUDITOR_ACTIONS}


def fetch_users():
    query = """
        SELECT u.UserId, u.UserName, u.CreatedDateTime, r.RoleName
        FROM dbo.tblUsers u
        JOIN dbo.tblRoles r ON r.RoleId = u.RoleId
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()


def main():
    users = fetch_users()
    if not users:
        print("No users found - run test_users.py first.")
        return

    insert_query = """
        INSERT INTO dbo.tblAuditLog
            (UserName, UserRole, UserId, UserCreatedDateTime, UserLoginDateTime,
             IpAddress, ModifiedPageOrField, ModifiedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """

    total_inserted = 0
    with get_connection() as conn:
        cursor = conn.cursor()
        for user in users:
            actions = ACTIONS_BY_ROLE.get(user.RoleName, [])
            num_entries = random.randint(2, 4)
            for _ in range(num_entries):
                login_time = datetime.now() - timedelta(hours=random.randint(1, 72))
                modified_at = login_time + timedelta(minutes=random.randint(1, 45))
                cursor.execute(
                    insert_query,
                    user.UserName,
                    user.RoleName,
                    user.UserId,
                    user.CreatedDateTime,
                    login_time,
                    random.choice(SAMPLE_IPS),
                    random.choice(actions) if actions else "General access",
                    modified_at,
                )
                total_inserted += 1
        conn.commit()

    print(f"Inserted {total_inserted} audit log entries for {len(users)} users.")


if __name__ == "__main__":
    main()