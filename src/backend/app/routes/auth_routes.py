from http import HTTPStatus
from sys import prefix
from app.models import user
from fastapi import APIRouter,Depends,HTTPException,status

from sqlalchemy.orm import session 
from app.database import get_db
from app.schemas.auth import SignupResponse,SingupRequest
from app.password import pwd_hash
from app.models.user import User

router = APIRouter(prefix="/auth",tags=["Authentication"])

@router.post("/signup",response_model=SignupResponse,status_code=status.HTTP_201_created)
def signup(
    data : SingupRequest,
    db:session = Depends=get_db
):
    existing_user = (db.query(user).filter(user.email == data.email).first())

    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,details = "email already registered")

    user = User(name=data.name,email=data.email,password_hash=pwd_hash(data.password))

    db.add(user)
    db.commit()
    db.refresh(user)

    return user