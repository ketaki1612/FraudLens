"""
Password hashing and JWT token handling for login/authentication.

SECRET_KEY should come from an environment variable in any real
deployment - the fallback here is only for local development.
"""

import os
from datetime import datetime, timedelta

import pyotp
from jose import jwt, JWTError
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-only-secret-change-this-before-hosting")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours
MFA_PENDING_TOKEN_EXPIRE_MINUTES = 5  # short-lived - just enough time to enter the code


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    """data should contain user_id, username, role_name, created_date_time, login_date_time."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_pending_token(user_id: int) -> str:
    """
    A short-lived, limited-purpose token issued right after password
    verification when MFA is enabled - proves "this person already
    entered the correct password" without yet being a full access
    token. The MFA verify endpoint checks for mfa_pending=True.
    """
    to_encode = {
        "user_id": user_id,
        "mfa_pending": True,
        "exp": datetime.utcnow() + timedelta(minutes=MFA_PENDING_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_setup_pending_token(user_id: int) -> str:
    """
    Like create_mfa_pending_token, but for a user who hasn't enrolled
    in MFA yet at all. This token ONLY allows calling the MFA
    setup/verify endpoints - nothing else - until enrollment completes.
    MFA is mandatory, so this is issued instead of a real access token.
    """
    to_encode = {
        "user_id": user_id,
        "setup_pending": True,
        "exp": datetime.utcnow() + timedelta(minutes=10),
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raises jose.JWTError if the token is invalid or expired."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def generate_mfa_secret() -> str:
    """Generates a new random base32 TOTP secret for a user enrolling in MFA."""
    return pyotp.random_base32()


def get_mfa_provisioning_uri(secret: str, username: str) -> str:
    """
    Returns an otpauth:// URI that authenticator apps (Google/Microsoft
    Authenticator, Authy, etc.) understand when rendered as a QR code.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="CC Transaction Monitor"
    )


def verify_totp_code(secret: str, code: str) -> bool:
    """Checks a 6-digit code against the secret, allowing normal clock drift."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)