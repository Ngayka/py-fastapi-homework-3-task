import re
from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str
    email: EmailStr

    @field_validator("password")
    def check_password(cls, value:str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True
    }

class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    pass

class MessageResponseSchema(BaseModel):
    message: str
    pass

class PasswordResetRequestSchema(BaseModel):
    email: EmailStr
    pass

class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str
    pass

class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    pass