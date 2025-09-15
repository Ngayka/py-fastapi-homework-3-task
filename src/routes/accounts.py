from datetime import datetime, timezone
from typing import cast
from jose import ExpiredSignatureError, JWTError

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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
    )

from security.passwords import hash_password, verify_password


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
             status_code=status.HTTP_200_OK)

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


@router.post("/login/",
             response_model=UserLoginResponseSchema,
             status_code=status.HTTP_200_OK
             )
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
        ):
    result = await db.execute(
        select(UserModel).where(
            UserModel.email == login_data.email))
    user = result.scalars().first()
    if not user or not user.verify_password(login_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"sub": str(user.id)})
    refresh_token = jwt_manager.create_refresh_token({"sub": str(user.id)})

    try:
        new_refresh_token = RefreshTokenModel(user=user.id, token=refresh_token)
        db.add(new_refresh_token)
        await db.commit()

    except:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post("/api/v1/accounts/refresh/",
             response_model=TokenRefreshResponseSchema,
             status_code=status.HTTP_200_OK)

async def refresh_token(
    refresh_data = TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)):
    result = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_data.refresh_token
    ))
    token_obj = result.scalars().first()
    if not token_obj:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    try:
        validated_data = jwt_manager.decode_refresh_token(token_obj.token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user_id = validated_data.get("sub")
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})

    return TokenRefreshResponseSchema(access_token=access_token)