from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, constr


class TransactionCreate(BaseModel):
    """Fields required to insert a new transaction."""
    last4_digits: constr(min_length=4, max_length=4, pattern=r"^\d{4}$")
    location: constr(min_length=1, max_length=100)
    merchant_id: int
    item_description: Optional[str] = None
    amount: float = Field(gt=0)
    currency_code: constr(min_length=3, max_length=3)
    transaction_date_time: datetime
    channel: str


class TransactionOut(TransactionCreate):
    """Fields returned when reading a transaction back out."""
    transaction_id: int
    risk_score: Optional[float] = None
    is_risky: bool = False
    status: str = "Pending"
    created_at: datetime


class RuleCreate(BaseModel):
    """Fields required to create a new fraud rule."""
    rule_key: str
    rule_name: str
    description: str
    condition_type: str
    parameters: dict
    points: float
    is_active: bool = True


class RuleUpdate(BaseModel):
    """Fields that can be changed on an existing rule. All optional -
    only the fields the admin actually changed need to be sent."""
    rule_name: Optional[str] = None
    description: Optional[str] = None
    condition_type: Optional[str] = None
    parameters: Optional[dict] = None
    points: Optional[float] = None
    is_active: Optional[bool] = None


class RuleOut(BaseModel):
    """A fraud rule as returned to the frontend."""
    rule_id: int
    rule_key: str
    rule_name: str
    description: str
    condition_type: str
    parameters: dict
    points: float
    is_active: bool


class UserRegister(BaseModel):
    """Fields required to create a new user account."""
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=8)
    role_name: str  # "Admin" / "Analyst" / "Auditor"


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    """A user as returned to the frontend - never includes the password."""
    user_id: int
    username: str
    role_name: str
    is_active: bool
    created_date_time: datetime
    last_login_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class AuditLogOut(BaseModel):
    """One audit log entry as returned to the frontend."""
    audit_id: int
    user_name: str
    user_role: str
    user_id: int
    user_created_date_time: datetime
    user_login_date_time: datetime
    ip_address: Optional[str] = None
    modified_page_or_field: str
    modified_at: datetime


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaVerifyRequest(BaseModel):
    code: constr(min_length=6, max_length=6)


class MfaLoginRequest(BaseModel):
    pending_token: str
    code: constr(min_length=6, max_length=6)


class AdminResetPasswordRequest(BaseModel):
    new_password: constr(min_length=8)