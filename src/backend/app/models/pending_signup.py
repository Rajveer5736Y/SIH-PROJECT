from sqlalchemy import Column, Integer, String, DateTime,Boolean

from app.database import Base

class PendingSignup(Base):
    __tablename__ = "pending_signups"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # "trainer" or "trainee"
    otp_code = Column(String, nullable=False)
    otp_expiry = Column(DateTime, nullable=False)