from pydantic import BaseModel, Field, EmailStr
from typing import Literal


class SignupRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Literal["trainee", "trainer"]


class SignupResponse(BaseModel):
    message: str
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    is_verified: bool
    role: str

    model_config = {
        "from_attributes": True
    }


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=128)


class LoginResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str


class PDFUploadResponse(BaseModel):
    id: int
    title: str
    subject: str
    file_name: str
    file_type: str

    class Config:
        from_attributes = True