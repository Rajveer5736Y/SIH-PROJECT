import random
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.text import MIMEText
import os

from http import HTTPStatus
from sys import prefix
from fastapi import APIRouter,Depends,HTTPException,status

from sqlalchemy.orm import session 
from app.database import get_db
from app.schemas.auth import LoginResponse, SignupResponse,SignupRequest,LoginRequest, OTPVerifyRequest, UserResponse
from app.password import pwd_hash, verify_password
from app.models.user import User
from app.models.pending_signup import PendingSignup

router = APIRouter(prefix="/auth",tags=["Authentication"])

import os

EMAIL_CONFIG = {
    "sender": os.getenv("EMAIL_SENDER"),
    "password": os.getenv("EMAIL_APP_PASSWORD"),
}

OTP_EXPIRY_MINUTES = 5


def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def send_otp_email(email: str, otp: str):
    print(otp) 
    msg = MIMEText(f"Your OTP for Food Ordering App signup is: {otp}") 
    msg['Subject'] = 'OTP Verification' 
    msg['From'] = EMAIL_CONFIG['sender'] 
    msg['To'] = email 
    try: 
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server: 
            server.login(EMAIL_CONFIG['sender'], EMAIL_CONFIG['password']) 
            server.send_message(msg)
    except Exception as e: 
        print("Email Error", str(e)) 
    print(f"Sending OTP {otp} to {email}")


@router.post("/signup",response_model=SignupResponse,status_code=status.HTTP_201_CREATED)
def signup(
    data : SignupRequest,
    db:session = Depends(get_db)
):
    existing_user = (db.query(User).filter(User.email == data.email).first())

    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail= "email already registered")

    otp_code = generate_otp()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

    existing_pending = db.query(PendingSignup).filter(PendingSignup.email == data.email).first()

    if existing_pending:
        existing_pending.name = data.name
        existing_pending.password_hash = pwd_hash(data.password)
        existing_pending.otp_code = otp_code
        existing_pending.otp_expiry = expiry
    else:
        existing_pending = PendingSignup(
            name=data.name,
            email=data.email,
            password_hash=pwd_hash(data.password),
            otp_code=otp_code,
            otp_expiry=expiry,
        )
        db.add(existing_pending)

    db.commit()

    send_otp_email(data.email, otp_code)

    return SignupResponse(message="OTP sent to your email", email=data.email)


@router.post("/verify-otp",response_model=UserResponse,status_code=status.HTTP_200_OK)
def verify_otp(
    data: OTPVerifyRequest,
    db: session = Depends(get_db)
):
    pending = db.query(PendingSignup).filter(PendingSignup.email == data.email).first()

    if not pending:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no pending signup found for this email")

    if pending.otp_code != data.otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid otp")

    if datetime.now(timezone.utc) > pending.otp_expiry.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="otp expired")

    new_user = User(
        name=pending.name,
        email=pending.email,
        password_hash=pending.password_hash,
        is_verified=True,
    )

    db.add(new_user)
    db.delete(pending)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login",response_model=LoginResponse,status_code=status.HTTP_200_OK)
def login(data: LoginRequest,db:session = Depends(get_db)):
    
    existing_user = (db.query(User).filter(User.name == data.name).first())

    if not existing_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail = "USER DOES NOT EXISTS!")

    if verify_password(data.password,existing_user.password_hash):
        return LoginResponse(
            id=existing_user.id,
            name=existing_user.name,
            email=existing_user.email
        )
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="INCORRECT USERNAME OR PASSWORD!")