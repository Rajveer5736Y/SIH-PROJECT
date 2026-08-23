from pydantic import BaseModel, Field, EmailStr


class SignupRequest(BaseModel):
    name: str = Field(
        min_length=3,
        max_length=80
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128
    )

class SignupResponse(BaseModel):
    id: int
    name: str
    email: EmailStr

    model_config = {
        "from_attributes": True
    }

class LoginResponse(BaseModel):
    id:int
    name:str
    email:EmailStr

class LoginRequest(BaseModel):
    name:str = Field(
        min_length=3,
        max_length=80
    )
    password:str = Field(
        min_length=8,
        max_lenght=128
    )