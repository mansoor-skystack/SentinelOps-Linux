import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelops.db").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class IncidentRecord(Base):
    __tablename__ = "incident_records"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(120), default="web-console")
    source_type = Column(String(50), default="manual")
    stack_tag = Column(String(50), default="Linux")
    cpu_load = Column(Float, default=0.0)
    mem_used_pct = Column(Float, default=0.0)
    disk_used_pct = Column(Float, default=0.0)
    sanitized_log = Column(Text)
    root_cause = Column(Text)
    diagnostic_commands = Column(Text)
    fix_commands = Column(Text)
    risk_level = Column(String(20), default="SAFE")
    citations = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
