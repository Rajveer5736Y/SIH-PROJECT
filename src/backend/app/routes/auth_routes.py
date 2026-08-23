from http import HTTPStatus
from sys import prefix
from fastapi import APIRouter,Depends,HTTPException,status

from sqlalchemy.orm import session 
from app.database import get_db
from app.schemas.auth import LoginResponse, SignupResponse,SignupRequest,LoginRequest
from app.password import pwd_hash, verify_password
from app.models.user import User

router = APIRouter(prefix="/auth",tags=["Authentication"])

@router.post("/signup",response_model=SignupResponse,status_code=status.HTTP_201_CREATED)
def signup(
    data : SignupRequest,
    db:session = Depends(get_db)
):
    existing_user = (db.query(User).filter(User.email == data.email).first())

    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail= "email already registered")

    new_user = User(name=data.name,email=data.email,password_hash=pwd_hash(data.password))

    db.add(new_user)
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


    