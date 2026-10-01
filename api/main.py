"""
Minimal FastAPI service for tblStoreTransactionLogs.

Run with:
    uvicorn main:app --reload

Then open http://127.0.0.1:8000/docs for interactive API docs,
and see the /frontend/index.html file for a plain HTML page
that displays this data.
"""

import json
from datetime import datetime
from typing import List

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from db import get_connection
from models import (
    TransactionCreate, TransactionOut, RuleCreate, RuleUpdate, RuleOut,
    UserRegister, UserLogin, UserOut, TokenResponse, AuditLogOut,
    MfaSetupResponse, MfaVerifyRequest, MfaLoginRequest, AdminResetPasswordRequest,
)
from rules import evaluate_rules
from ml_scoring import get_ml_score
from auth import (
    hash_password, verify_password, create_access_token, decode_access_token,
    create_mfa_pending_token, create_setup_pending_token,
    generate_mfa_secret, get_mfa_provisioning_uri, verify_totp_code,
)

app = FastAPI(title="CC Transaction Monitoring API")

# Allow the simple frontend (opened as a local file or served separately)
# to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # fine for local learning project; restrict in real use
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok", "message": "CC Transaction Monitoring API is running"}


# --- Auth ---------------------------------------------------------------

security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependency that verifies the JWT sent in the Authorization header and
    returns the decoded payload (user_id, username, role_name).
    Use this on any endpoint that requires the caller to be logged in.
    """
    try:
        payload = decode_access_token(credentials.credentials)
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user_optional(credentials: HTTPAuthorizationCredentials = Depends(optional_security)) -> dict | None:
    """
    Like get_current_user, but returns None instead of raising when no
    token is provided at all. Used for /api/auth/register's bootstrap
    logic (the very first user can register without being logged in).
    A token that IS provided but invalid still raises 401.
    """
    if credentials is None:
        return None
    try:
        return decode_access_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(*allowed_roles: str):
    """
    Dependency factory for role-gating an endpoint, e.g.:
        @app.post(..., dependencies=[Depends(require_role("Admin"))])
    """
    def checker(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role_name") not in allowed_roles:
            raise HTTPException(status_code=403, detail="You don't have permission to do this")
        return user
    return checker


def get_user_for_mfa_actions(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Accepts EITHER a full logged-in session OR a short-lived
    setup-pending token (issued by /login when MFA enrollment is
    mandatory and hasn't happened yet). Both contain user_id, which is
    all the MFA setup/verify endpoints actually need - this lets a
    brand-new user complete mandatory enrollment before ever having
    full access, while also letting an already-logged-in user
    voluntarily re-enroll later using their normal session.
    """
    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if "user_id" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


def write_audit_log(user: dict, request: Request, modified_page_or_field: str):
    """
    Inserts one row into tblAuditLog for an authenticated action.
    `user` is the decoded JWT payload from get_current_user/require_role.
    `Hostname` actually stores the requester's IP address - a web server
    cannot see a visitor's real machine hostname, only their IP.
    """
    client_ip = request.client.host if request.client else None

    insert_query = """
        INSERT INTO dbo.tblAuditLog
            (UserName, UserRole, UserId, UserCreatedDateTime, UserLoginDateTime,
             IpAddress, ModifiedPageOrField, ModifiedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME())
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            insert_query,
            user["username"],
            user["role_name"],
            user["user_id"],
            datetime.fromisoformat(user["created_date_time"]),
            datetime.fromisoformat(user["login_date_time"]),
            client_ip,
            modified_page_or_field,
        )
        conn.commit()


@app.get("/api/users", response_model=List[UserOut])
def list_users(current_user: dict = Depends(require_role("Admin"))):
    """Returns all users, for the Settings page's User Management table. Admin only."""
    query = """
        SELECT u.UserId, u.UserName, u.IsActive, u.CreatedDateTime, u.LastLoginAt, r.RoleName
        FROM dbo.tblUsers u
        JOIN dbo.tblRoles r ON r.RoleId = u.RoleId
        ORDER BY u.CreatedDateTime DESC
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

    return [
        UserOut(
            user_id=row.UserId, username=row.UserName, role_name=row.RoleName,
            is_active=bool(row.IsActive), created_date_time=row.CreatedDateTime,
            last_login_at=row.LastLoginAt,
        )
        for row in rows
    ]


@app.get("/api/audit-logs", response_model=List[AuditLogOut])
def list_audit_logs(limit: int = 200, current_user: dict = Depends(require_role("Admin", "Auditor"))):
    """Returns audit log entries, newest first. Admin and Auditor only (not Analyst)."""
    query = """
        SELECT TOP (?)
            AuditId, UserName, UserRole, UserId, UserCreatedDateTime,
            UserLoginDateTime, IpAddress, ModifiedPageOrField, ModifiedAt
        FROM dbo.tblAuditLog
        ORDER BY ModifiedAt DESC
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, limit)
        rows = cursor.fetchall()

    return [
        AuditLogOut(
            audit_id=row.AuditId, user_name=row.UserName, user_role=row.UserRole,
            user_id=row.UserId, user_created_date_time=row.UserCreatedDateTime,
            user_login_date_time=row.UserLoginDateTime, ip_address=row.IpAddress,
            modified_page_or_field=row.ModifiedPageOrField, modified_at=row.ModifiedAt,
        )
        for row in rows
    ]


@app.post("/api/auth/register", response_model=UserOut, status_code=201)
def register(user: UserRegister, current_user: dict | None = Depends(get_current_user_optional)):
    """
    Creates a new user account.
      - BOOTSTRAP: if tblUsers is currently empty, registration is open
        (so the very first Admin account can be created).
      - Otherwise, only a logged-in Admin can register new users.
    Also enforces:
      - role_name must be Admin, Analyst, or Auditor
      - only 1 active Admin allowed (also enforced at the DB level as a backstop)
      - only 2 active Auditors allowed at a time
    """
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM dbo.tblUsers")
        total_users = cursor.fetchone()[0]

        if total_users > 0:
            if current_user is None or current_user.get("role_name") != "Admin":
                raise HTTPException(status_code=403, detail="Only an Admin can register new users")

        cursor.execute("SELECT RoleId FROM dbo.tblRoles WHERE RoleName = ?", user.role_name)
        role_row = cursor.fetchone()
        if role_row is None:
            raise HTTPException(status_code=400, detail="role_name must be Admin, Analyst, or Auditor")
        role_id = role_row[0]

        if user.role_name == "Admin":
            cursor.execute("SELECT COUNT(*) FROM dbo.tblUsers WHERE RoleId = ? AND IsActive = 1", role_id)
            if cursor.fetchone()[0] >= 1:
                raise HTTPException(status_code=409, detail="An active Admin already exists")

        if user.role_name == "Auditor":
            cursor.execute("SELECT COUNT(*) FROM dbo.tblUsers WHERE RoleId = ? AND IsActive = 1", role_id)
            if cursor.fetchone()[0] >= 2:
                raise HTTPException(status_code=409, detail="Maximum of 2 active Auditors already reached")

        try:
            cursor.execute(
                """INSERT INTO dbo.tblUsers (UserName, PasswordHash, RoleId)
                   OUTPUT INSERTED.UserId, INSERTED.CreatedDateTime
                   VALUES (?, ?, ?)""",
                user.username, hash_password(user.password), role_id,
            )
            new_id, created_at = cursor.fetchone()
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e).upper():
                raise HTTPException(status_code=409, detail=f"Username '{user.username}' already exists")
            raise

    return UserOut(
        user_id=new_id, username=user.username, role_name=user.role_name,
        is_active=True, created_date_time=created_at, last_login_at=None,
    )


MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


@app.post("/api/auth/login")
def login(credentials: UserLogin):
    """
    Verifies username/password. If MFA is enabled for this user, does
    NOT return a full access token yet - instead returns
    {"mfa_required": true, "pending_token": "..."} and the caller must
    call POST /api/auth/login/mfa with that token + a TOTP code to
    actually get logged in. If MFA isn't enabled, behaves as before.

    PCI DSS 8.3.4: locks the account for LOCKOUT_DURATION_MINUTES after
    MAX_FAILED_LOGIN_ATTEMPTS consecutive wrong passwords, so a brute
    force password guesser hits a hard wall regardless of RBAC/session
    protections that only apply AFTER a successful login.

    (No single response_model here since the two possible response
    shapes differ - both are still valid, documented JSON.)
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT u.UserId, u.UserName, u.PasswordHash, u.IsActive,
                      u.CreatedDateTime, u.LastLoginAt, u.MfaEnabled, r.RoleName,
                      u.FailedLoginAttempts, u.LockedUntil
               FROM dbo.tblUsers u
               JOIN dbo.tblRoles r ON r.RoleId = u.RoleId
               WHERE u.UserName = ?""",
            credentials.username,
        )
        row = cursor.fetchone()

        # Same generic error whether the username doesn't exist or the
        # account is locked/wrong password - don't reveal which case it is.
        generic_error = HTTPException(status_code=401, detail="Incorrect username or password")

        if row is None:
            raise generic_error

        if row.LockedUntil and row.LockedUntil > datetime.utcnow():
            minutes_left = int((row.LockedUntil - datetime.utcnow()).total_seconds() / 60) + 1
            raise HTTPException(
                status_code=403,
                detail=f"Account locked due to repeated failed attempts. Try again in {minutes_left} minute(s).",
            )

        if not verify_password(credentials.password, row.PasswordHash):
            new_attempts = row.FailedLoginAttempts + 1
            if new_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                cursor.execute(
                    """UPDATE dbo.tblUsers
                       SET FailedLoginAttempts = 0,
                           LockedUntil = DATEADD(MINUTE, ?, SYSUTCDATETIME())
                       WHERE UserId = ?""",
                    LOCKOUT_DURATION_MINUTES, row.UserId,
                )
                conn.commit()
                raise HTTPException(
                    status_code=403,
                    detail=f"Account locked due to repeated failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes.",
                )
            cursor.execute(
                "UPDATE dbo.tblUsers SET FailedLoginAttempts = ? WHERE UserId = ?",
                new_attempts, row.UserId,
            )
            conn.commit()
            raise generic_error

        if not row.IsActive:
            raise HTTPException(status_code=403, detail="This account is deactivated")

        # Correct password - reset the failed-attempt counter.
        cursor.execute(
            "UPDATE dbo.tblUsers SET FailedLoginAttempts = 0, LockedUntil = NULL WHERE UserId = ?",
            row.UserId,
        )
        conn.commit()

        if row.MfaEnabled:
            # Don't update LastLoginAt or issue a real token yet - that
            # happens after the MFA code is verified in /login/mfa.
            pending_token = create_mfa_pending_token(row.UserId)
            return {"mfa_required": True, "pending_token": pending_token}

        # MFA is MANDATORY: if not enrolled yet, no real access is granted
        # at all - only a limited token that can call the MFA setup/verify
        # endpoints, nothing else. Enrollment must complete before login
        # succeeds for the first time.
        setup_token = create_setup_pending_token(row.UserId)
        return {"mfa_setup_required": True, "setup_token": setup_token}


@app.post("/api/auth/login/mfa", response_model=TokenResponse)
def login_mfa(payload: MfaLoginRequest):
    """Second step of login when MFA is enabled: verify the pending_token + TOTP code."""
    try:
        pending_payload = decode_access_token(payload.pending_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="MFA session expired - please log in again")

    if not pending_payload.get("mfa_pending"):
        raise HTTPException(status_code=401, detail="Invalid MFA session")

    user_id = pending_payload["user_id"]

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT u.UserId, u.UserName, u.IsActive, u.CreatedDateTime,
                      u.MfaSecret, r.RoleName
               FROM dbo.tblUsers u
               JOIN dbo.tblRoles r ON r.RoleId = u.RoleId
               WHERE u.UserId = ?""",
            user_id,
        )
        row = cursor.fetchone()

        if row is None or not row.IsActive:
            raise HTTPException(status_code=403, detail="Account not found or deactivated")
        if not verify_totp_code(row.MfaSecret, payload.code):
            raise HTTPException(status_code=401, detail="Incorrect MFA code")

        cursor.execute(
            "UPDATE dbo.tblUsers SET LastLoginAt = SYSUTCDATETIME() WHERE UserId = ?",
            row.UserId,
        )
        conn.commit()

    token = create_access_token({
        "user_id": row.UserId, "username": row.UserName, "role_name": row.RoleName,
        "created_date_time": row.CreatedDateTime.isoformat(),
        "login_date_time": datetime.utcnow().isoformat(),
    })

    return TokenResponse(
        access_token=token,
        user=UserOut(
            user_id=row.UserId, username=row.UserName, role_name=row.RoleName,
            is_active=True, created_date_time=row.CreatedDateTime, last_login_at=None,
        ),
    )


@app.post("/api/auth/mfa/setup", response_model=MfaSetupResponse)
def setup_mfa(current_user: dict = Depends(get_user_for_mfa_actions)):
    """
    Generates a new TOTP secret and stores it (MfaEnabled stays False
    until verified - see /mfa/verify). Works both for a brand-new user
    completing MANDATORY first-time enrollment (setup-pending token,
    no full session yet) and an existing user voluntarily re-enrolling
    (normal full session). Calling this again before verifying
    overwrites the pending secret, which is fine (e.g. rescanning).
    """
    user_id = current_user["user_id"]
    secret = generate_mfa_secret()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE dbo.tblUsers SET MfaSecret = ?, MfaEnabled = 0 WHERE UserId = ?",
            secret, user_id,
        )
        conn.commit()

        cursor.execute("SELECT UserName FROM dbo.tblUsers WHERE UserId = ?", user_id)
        username = cursor.fetchone()[0]

    uri = get_mfa_provisioning_uri(secret, username)
    return MfaSetupResponse(secret=secret, provisioning_uri=uri)


@app.post("/api/auth/mfa/verify")
def verify_mfa_setup(payload: MfaVerifyRequest, current_user: dict = Depends(get_user_for_mfa_actions)):
    """
    Confirms enrollment by checking one real code from the
    authenticator app, then flips MfaEnabled on.

    If this came from a setup-pending token (mandatory first-time
    enrollment, no full session yet), a full access token is issued
    immediately - completing enrollment IS the login, so the user
    doesn't have to separately log in again right after. If it came
    from an already-logged-in user re-enrolling voluntarily, just
    confirms success without changing their existing session.
    """
    user_id = current_user["user_id"]

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT u.MfaSecret, u.UserName, u.CreatedDateTime, r.RoleName
               FROM dbo.tblUsers u JOIN dbo.tblRoles r ON r.RoleId = u.RoleId
               WHERE u.UserId = ?""",
            user_id,
        )
        row = cursor.fetchone()

        if row is None or not row.MfaSecret:
            raise HTTPException(status_code=400, detail="No MFA setup in progress - call /mfa/setup first")
        if not verify_totp_code(row.MfaSecret, payload.code):
            raise HTTPException(status_code=401, detail="Incorrect code - check your authenticator app and try again")

        cursor.execute("UPDATE dbo.tblUsers SET MfaEnabled = 1 WHERE UserId = ?", user_id)

        if current_user.get("setup_pending"):
            cursor.execute("UPDATE dbo.tblUsers SET LastLoginAt = SYSUTCDATETIME() WHERE UserId = ?", user_id)
        conn.commit()

    if current_user.get("setup_pending"):
        token = create_access_token({
            "user_id": user_id, "username": row.UserName, "role_name": row.RoleName,
            "created_date_time": row.CreatedDateTime.isoformat(),
            "login_date_time": datetime.utcnow().isoformat(),
        })
        return TokenResponse(
            access_token=token,
            user=UserOut(
                user_id=user_id, username=row.UserName, role_name=row.RoleName,
                is_active=True, created_date_time=row.CreatedDateTime, last_login_at=None,
            ),
        )

    return {"mfa_enabled": True}


@app.post("/api/users/{user_id}/reset-password")
def admin_reset_password(user_id: int, payload: AdminResetPasswordRequest, request: Request,
                          current_user: dict = Depends(require_role("Admin"))):
    """Admin sets a new password for a user directly (no email flow) - share it with them privately."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE dbo.tblUsers SET PasswordHash = ? WHERE UserId = ?",
            hash_password(payload.new_password), user_id,
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()

    write_audit_log(current_user, request, f"Settings > Reset password for user id {user_id}")
    return {"status": "password reset"}


@app.get("/api/rules", response_model=List[RuleOut])
def list_rules(current_user: dict = Depends(get_current_user)):
    """Returns every fraud rule (active and inactive). Any logged-in role can view."""
    query = """
        SELECT RuleId, RuleKey, RuleName, Description, ConditionType,
               ParametersJson, Points, IsActive
        FROM dbo.tblFraudRules
        ORDER BY RuleId
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

    return [
        RuleOut(
            rule_id=row.RuleId,
            rule_key=row.RuleKey,
            rule_name=row.RuleName,
            description=row.Description,
            condition_type=row.ConditionType,
            parameters=json.loads(row.ParametersJson),
            points=float(row.Points),
            is_active=bool(row.IsActive),
        )
        for row in rows
    ]


@app.post("/api/rules", response_model=RuleOut, status_code=201)
def create_rule(rule: RuleCreate, request: Request, current_user: dict = Depends(require_role("Admin"))):
    """Creates a new fraud rule. Admin only."""
    insert_query = """
        INSERT INTO dbo.tblFraudRules
            (RuleKey, RuleName, Description, ConditionType, ParametersJson, Points, IsActive)
        OUTPUT INSERTED.RuleId
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                insert_query,
                rule.rule_key,
                rule.rule_name,
                rule.description,
                rule.condition_type,
                json.dumps(rule.parameters),
                rule.points,
                rule.is_active,
            )
            new_id = cursor.fetchone()[0]
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e).upper() or "DUPLICATE" in str(e).upper():
                raise HTTPException(status_code=409, detail=f"rule_key '{rule.rule_key}' already exists")
            raise

    write_audit_log(current_user, request, f"Fraud Rules > Created rule: {rule.rule_key}")
    return RuleOut(rule_id=new_id, **rule.model_dump())


@app.put("/api/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: int, rule: RuleUpdate, request: Request, current_user: dict = Depends(require_role("Admin"))):
    """Updates one or more fields on an existing rule. Admin only. Only send the fields that changed."""
    updates = rule.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided to update")

    set_clauses = []
    values = []
    for field, value in updates.items():
        column_map = {
            "rule_name": "RuleName", "description": "Description",
            "condition_type": "ConditionType", "points": "Points",
            "is_active": "IsActive",
        }
        if field == "parameters":
            set_clauses.append("ParametersJson = ?")
            values.append(json.dumps(value))
        elif field in column_map:
            set_clauses.append(f"{column_map[field]} = ?")
            values.append(value)

    set_clauses.append("UpdatedAt = SYSUTCDATETIME()")
    values.append(rule_id)

    update_query = f"""
        UPDATE dbo.tblFraudRules
        SET {', '.join(set_clauses)}
        WHERE RuleId = ?
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(update_query, values)
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.commit()

        cursor.execute(
            """SELECT RuleId, RuleKey, RuleName, Description, ConditionType,
                      ParametersJson, Points, IsActive
               FROM dbo.tblFraudRules WHERE RuleId = ?""",
            rule_id,
        )
        row = cursor.fetchone()

    changed_fields = ", ".join(updates.keys())
    write_audit_log(current_user, request, f"Fraud Rules > Updated rule id {rule_id}: {changed_fields}")

    return RuleOut(
        rule_id=row.RuleId, rule_key=row.RuleKey, rule_name=row.RuleName,
        description=row.Description, condition_type=row.ConditionType,
        parameters=json.loads(row.ParametersJson), points=float(row.Points),
        is_active=bool(row.IsActive),
    )


@app.delete("/api/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, request: Request, current_user: dict = Depends(require_role("Admin"))):
    """Deletes a rule permanently. Admin only."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dbo.tblFraudRules WHERE RuleId = ?", rule_id)
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.commit()

    write_audit_log(current_user, request, f"Fraud Rules > Deleted rule id {rule_id}")


@app.get("/api/transactions", response_model=List[TransactionOut])
def list_transactions(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Fetch the most recent transactions, newest first. Any logged-in role can view."""
    query = """
        SELECT TOP (?)
            TransactionId, Last4Digits, Location, MerchantId,
            ItemDescription, Amount, CurrencyCode, TransactionDateTime,
            Channel, RiskScore, IsRisky, Status, CreatedAt
        FROM dbo.tblStoreTransactionLogs
        ORDER BY TransactionDateTime DESC
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, limit)
        rows = cursor.fetchall()

    return [
        TransactionOut(
            transaction_id=row.TransactionId,
            last4_digits=row.Last4Digits,
            location=row.Location,
            merchant_id=row.MerchantId,
            item_description=row.ItemDescription,
            amount=float(row.Amount),
            currency_code=row.CurrencyCode,
            transaction_date_time=row.TransactionDateTime,
            channel=row.Channel,
            risk_score=float(row.RiskScore) if row.RiskScore is not None else None,
            is_risky=bool(row.IsRisky),
            status=row.Status,
            created_at=row.CreatedAt,
        )
        for row in rows
    ]


@app.get("/api/transactions/{transaction_id}", response_model=TransactionOut)
def get_transaction(transaction_id: int, current_user: dict = Depends(get_current_user)):
    """Fetch a single transaction by its ID. Any logged-in role can view."""
    query = """
        SELECT
            TransactionId, Last4Digits, Location, MerchantId,
            ItemDescription, Amount, CurrencyCode, TransactionDateTime,
            Channel, RiskScore, IsRisky, Status, CreatedAt
        FROM dbo.tblStoreTransactionLogs
        WHERE TransactionId = ?
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, transaction_id)
        row = cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Transaction not found")

    return TransactionOut(
        transaction_id=row.TransactionId,
        last4_digits=row.Last4Digits,
        location=row.Location,
        merchant_id=row.MerchantId,
        item_description=row.ItemDescription,
        amount=float(row.Amount),
        currency_code=row.CurrencyCode,
        transaction_date_time=row.TransactionDateTime,
        channel=row.Channel,
        risk_score=float(row.RiskScore) if row.RiskScore is not None else None,
        is_risky=bool(row.IsRisky),
        status=row.Status,
        created_at=row.CreatedAt,
    )


@app.post("/api/transactions", response_model=TransactionOut, status_code=201)
def create_transaction(txn: TransactionCreate, current_user: dict = Depends(require_role("Admin", "Analyst"))):
    """
    Insert a new transaction, run it through the rule engine to get
    IsRisky / Status / RiskScore, and return the created row.
    Admin and Analyst only - Auditor is read-only.
    """
    # Build a plain dict for the rule engine - it expects these exact keys.
    txn_dict = {
        "amount": txn.amount,
        "currency_code": txn.currency_code,
        "location": txn.location,
        "channel": txn.channel,
        "item_description": txn.item_description,
        "transaction_date_time": txn.transaction_date_time,
    }
    is_risky_rules, status_rules, rule_score = evaluate_rules(txn_dict)

    try:
        ml_score = get_ml_score(txn_dict)
    except FileNotFoundError:
        # Model hasn't been trained yet - fall back to rules only.
        ml_score = 0.0

    # Combine: rules get more weight since they're specific business
    # logic, ML adds a general "does this look unusual overall" signal.
    combined_score = min((rule_score * 0.6) + (ml_score * 0.4), 100.0)

    if combined_score >= 70:
        status = "Rejected"
    elif combined_score >= 20:
        status = "Flagged"
    else:
        status = "Approved"

    is_risky = bool(combined_score >= 20)
    risk_score = round(float(combined_score), 2)

    insert_query = """
        INSERT INTO dbo.tblStoreTransactionLogs
            (Last4Digits, Location, MerchantId, ItemDescription,
             Amount, CurrencyCode, TransactionDateTime, Channel,
             RiskScore, IsRisky, Status)
        OUTPUT INSERTED.TransactionId, INSERTED.CreatedAt
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            insert_query,
            txn.last4_digits,
            txn.location,
            txn.merchant_id,
            txn.item_description,
            txn.amount,
            txn.currency_code,
            txn.transaction_date_time,
            txn.channel,
            risk_score,
            is_risky,
            status,
        )
        new_id, created_at = cursor.fetchone()
        conn.commit()

    return TransactionOut(
        transaction_id=new_id,
        created_at=created_at,
        risk_score=risk_score,
        is_risky=is_risky,
        status=status,
        **txn.model_dump(),
    )