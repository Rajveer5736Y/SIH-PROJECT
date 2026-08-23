from app.database import Base
from sqlalchemy import Column,Integer,String,Boolean,DateTime,LargeBinary,ForeignKey

class StudyMaterial(Base):
    __tablename__ = "study_materials"

    id = Column(Integer, primary_key=True)
    teacher_id = Column(Integer, ForeignKey("Trainer.id"), nullable=False)

    title = Column(String(200), nullable=False)
    subject = Column(String(100), nullable=False)

    file_name = Column(String(255), nullable=False)
    file_type = Column(String(100), nullable=False)

    file_data = Column(LargeBinary, nullable=False)