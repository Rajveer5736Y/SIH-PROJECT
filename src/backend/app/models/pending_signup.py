from sqlalchemy import Column, Integer, String, DateTime

from app.database import Base


class PendingSignup(Base):
    __tablename__ = "pending_signups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    otp_code = Column(String(6), nullable=False)
    otp_expiry = Column(DateTime, nullable=False)