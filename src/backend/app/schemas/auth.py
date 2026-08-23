from pydantic import BaseModel, Field, EmailStr


class SignupRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role:str = Field(min_length=12,max_length=122)


class SignupResponse(BaseModel):
    message: str
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp:str
    is_trainer:bool


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    is_verified: bool
    is_trainer:bool

    model_config = {
        "from_attributes": True
    }


class LoginRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=128)


class LoginResponse(BaseModel):
    id: int
    name: str
    email: EmailStr

class PDFUploadResponse(BaseModel):
    id: int
    title: str
    subject: str
    file_name: str
    file_type: str

    class Config:
        from_attributes = True

    