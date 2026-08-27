"""Authentication and user schemas."""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    organization: Optional[str] = Field(default=None, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)
    accept_terms: bool = False

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter")
        return v

    @field_validator("confirm_password")
    @classmethod
    def confirm_matches(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v

    @field_validator("accept_terms")
    @classmethod
    def terms_accepted(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Terms and conditions must be accepted")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordUpdateRequest(BaseModel):
    """Set a password on an SSO-only account, or change an existing one.

    `current_password` is only required when a password already exists.
    """
    current_password: Optional[str] = Field(default=None, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter")
        return v

    @field_validator("confirm_password")
    @classmethod
    def confirm_matches(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: str
    organization: Optional[str] = None
    is_active: bool
    is_verified: bool
    last_login_at: Optional[datetime] = None
    oauth_provider: Optional[str] = None
    has_password: bool = False
    sso_blocked: bool = False
    two_factor_enabled: bool = False
    created_at: Optional[datetime] = None
    roles: List[str] = []

    @model_validator(mode="before")
    @classmethod
    def map_tfa_enabled(cls, data):
        """Map the ORM model's tfa_enabled attribute to two_factor_enabled."""
        if hasattr(data, "tfa_enabled"):
            data.two_factor_enabled = data.tfa_enabled
        elif isinstance(data, dict) and "tfa_enabled" in data:
            data["two_factor_enabled"] = data["tfa_enabled"]
        return data

    @field_validator("roles", mode="before")
    @classmethod
    def coerce_roles(cls, v):
        """Convert ORM Role objects to role names when validating from attributes."""
        if isinstance(v, list) and v and hasattr(v[0], "name"):
            return [r.name for r in v]
        return v


class AuthResponse(BaseModel):
    user: UserOut
    tokens: TokenResponse


class UserStatusUpdate(BaseModel):
    """Admin: enable or disable an account."""
    is_active: bool


class AdminPasswordReset(BaseModel):
    """Admin: force-set a user's password (no current password needed)."""
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter")
        return v


class UserRolesUpdate(BaseModel):
    """Admin: replace the roles on an account."""
    roles: List[str] = Field(min_length=1)


class UserSsoBlockUpdate(BaseModel):
    """Admin: block or allow SSO sign-in for an account."""
    blocked: bool


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class TwoFactorSetupResponse(BaseModel):
    secret: str
    uri: str
    enabled: bool


class TwoFactorVerifyRequest(BaseModel):
    code: str
    action: str = 'enable'  # 'enable' or 'disable' or 'verify'


class BackupCodeResponse(BaseModel):
    codes: list[str]
