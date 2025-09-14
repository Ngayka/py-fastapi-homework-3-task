from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema
)

from security.passwords import hash_password


router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code = 201,
    summary="Create a new user",
    )

async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    exiting_user = result.scalars().first()
    if exiting_user:
        raise HTTPException(status_code=409, detail=(f"A user with this email {user_data.email} already exists."))
    try:
        new_user = UserModel(
            email=user_data.email,
            _hashed_password = hash_password(user_data.password),
            group_id=1
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return UserRegistrationResponseSchema.model_validate(new_user)

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

@router.post("/activate/",
             response_model = MessageResponseSchema,
             status_code=201,
             summary="activate user account")

async def activate_user(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == user_data.token
        ).where(ActivationTokenModel.user.has(email == user_data.email)))

    token_obj = result.scalars().firts()

    expires_at_utc= cast(datetime, token_obj.expires_at).replace(tzinfo=timezone.utc)
    now_utc = cast(datetime, datetime.utcnow().replace(tzinfo=timezone.utc))

    if not token_obj or expires_at_utc < now_utc:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user = token_obj.user
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    await db.delete(token_obj)
    await db.commit()
    await db.refresh(user)
    return {"message": "User account activated successfully."}


