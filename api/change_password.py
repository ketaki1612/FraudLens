"""
One-off utility to change a user's password directly in the DB,
using the exact same hashing as the app (passlib/bcrypt) - so the
new password will work with the normal login endpoint.

Usage:
    python change_password.py <username> <new_password>

Example:
    python change_password.py ketaki.jadhav MyRealSecurePassword!2026
"""

import sys

from auth import hash_password
from db import get_connection


def main():
    if len(sys.argv) != 3:
        print("Usage: python change_password.py <username> <new_password>")
        return

    username, new_password = sys.argv[1], sys.argv[2]
    if len(new_password) < 8:
        print("Password must be at least 8 characters.")
        return

    hashed = hash_password(new_password)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE dbo.tblUsers SET PasswordHash = ? WHERE UserName = ?",
            hashed, username,
        )
        if cursor.rowcount == 0:
            print(f"No user found with username '{username}'")
            return
        conn.commit()

    print(f"Password updated for {username}.")


if __name__ == "__main__":
    main()