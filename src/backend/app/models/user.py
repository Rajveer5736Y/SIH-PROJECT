from enum import unique
import string
from sqlalchemy import Column,Integer,String,DateTime
from sqlalchemy.sql import func

from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
        )

    name = Column(
        String(255),
        nullable=False
        )

    email = Column(
        String(255),
        nullable=False,
        index=True,
        unique=True
        )

    password_hash = Column(String(255),nullable=False)

    created_at = Column(
        DateTime,
        server_default=func.now(),
        nullable=False
        )



