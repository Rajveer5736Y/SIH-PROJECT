from sqlalchemy.orm.session import Session 
import os 
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv("DATABSE_URL")

if not DB_URL:
    raise RuntimeError("DB url is missing")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

engine = create_engine(DB_URL)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


from typing import Generator

def get_db()->Generator[Session,None,None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
