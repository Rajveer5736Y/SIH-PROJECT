from enum import unique
import string
from sqlalchemy import Column,Integer,String,Boolean,DateTime
from sqlalchemy.sql import func

from app.database import Base

class Trainee(Base):
    __tablename__ = "Trainee"

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

    is_verified = Column(Boolean, default=True, nullable=False)
    role = Column(String(50),default="Trainee")
    created_at = Column(
        DateTime,
        server_default=func.now(),
        nullable=False
        )
        
class Trainer(Base):
    __tablename__ = "Trainer"

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
    role = Column(String(50),default="Trainer")
    is_verified = Column(Boolean, default=True, nullable=False)

    created_at = Column(
        DateTime,
        server_default=func.now(),
        nullable=False
        )


