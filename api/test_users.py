"""
Registers the initial set of users through the live API - so passwords
go through proper hashing and the max-1-Admin / max-2-Auditor checks
actually get exercised, same as a real registration would.

Usage:
    Make sure the API is running (uvicorn main:app --reload), then:
        python test_users.py

All seeded users get the same placeholder password (see PASSWORD
below) - change it before using this anywhere beyond local testing.
"""

import requests

API_URL = "http://127.0.0.1:8000/api/auth/register"
PASSWORD = "ChangeMe123!"  # placeholder - meets the 8-char minimum

USERS = [
    {"username": "ketaki.jadhav", "role_name": "Admin"},
    {"username": "priya.sharma", "role_name": "Analyst"},
    {"username": "james.wilson", "role_name": "Analyst"},
    {"username": "amara.okafor", "role_name": "Analyst"},
    {"username": "liam.chen", "role_name": "Analyst"},
    {"username": "sofia.rossi", "role_name": "Analyst"},
    {"username": "external.auditor", "role_name": "Auditor"},  # external auditor
    {"username": "internal.auditor", "role_name": "Auditor"},  # internal auditor
]


def main():
    for user in USERS:
        payload = {**user, "password": PASSWORD}
        try:
            res = requests.post(API_URL, json=payload, timeout=5)
            if res.status_code == 201:
                print(f"Created: {user['username']} ({user['role_name']})")
            else:
                print(f"Failed: {user['username']} -> {res.status_code} {res.json().get('detail')}")
        except requests.exceptions.ConnectionError:
            print("Could not connect to the API. Is uvicorn running?")
            return

    print(f"\nAll seeded users share the password: {PASSWORD}")


if __name__ == "__main__":
    main()