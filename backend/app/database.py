import os
from datetime import datetime
from sqlalchemy import create_engine, Column, ForeignKey, Integer, String, Text, DateTime, Float, inspect, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelops.db").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

def _enforce_remote_postgres_tls(database_url: URL) -> URL:
    if not database_url.drivername.startswith("postgresql") or database_url.host in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        return database_url

    query = dict(database_url.query)
    sslmode = query.get("sslmode", "")
    if not isinstance(sslmode, str) or sslmode.lower() not in {"require", "verify-ca", "verify-full"}:
        query["sslmode"] = "require"
    return database_url.set(query=query)


database_url = _enforce_remote_postgres_tls(make_url(DATABASE_URL))

connect_args = {"check_same_thread": False} if database_url.drivername.startswith("sqlite") else {}
engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
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
    status = Column(String(20), default="PENDING", nullable=False, server_default="PENDING")
    citations = Column(Text)
    diagnostic_report = Column(Text)
    remediation_report = Column(Text)
    post_check_report = Column(Text)
    remediation_approved_at = Column(DateTime)
    remediation_approved_by = Column(String(120))
    correlation_id = Column(Integer, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class RemediationAuditLog(Base):
    __tablename__ = "remediation_audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incident_records.id"), nullable=False, index=True)
    diagnostic_run_id = Column(String(64))
    actor = Column(String(120), nullable=False)
    approved_by = Column(String(120))
    outcome = Column(String(50), nullable=False)
    commands = Column(Text, nullable=False)
    execution_report = Column(Text, nullable=False)
    verification_report = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

class VisitorLog(Base):
    __tablename__ = "visitor_logs"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), index=True)
    city = Column(String(100), default="Unknown")
    region = Column(String(100), default="Unknown")
    country = Column(String(100), default="Unknown")
    isp = Column(String(150), default="Unknown")
    browser_os = Column(String(200), default="Unknown")
    referrer = Column(String(250), default="Direct")
    accept_language = Column(String(100), default="Unknown")
    path = Column(String(150), default="/")
    visited_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
    visitor_columns = {
        column["name"]
        for column in inspect(engine).get_columns("visitor_logs")
    }
    incident_columns = {
        column["name"]
        for column in inspect(engine).get_columns("incident_records")
    }
    additions = {
        "city": "VARCHAR(100) DEFAULT 'Unknown'",
        "region": "VARCHAR(100) DEFAULT 'Unknown'",
        "country": "VARCHAR(100) DEFAULT 'Unknown'",
        "isp": "VARCHAR(150) DEFAULT 'Unknown'",
        "browser_os": "VARCHAR(200) DEFAULT 'Unknown'",
        "referrer": "VARCHAR(250) DEFAULT 'Direct'",
        "accept_language": "VARCHAR(100) DEFAULT 'Unknown'",
    }
    incident_additions = {
        "diagnostic_report": "TEXT",
        "remediation_report": "TEXT",
        "post_check_report": "TEXT",
        "remediation_approved_at": "TIMESTAMP",
        "remediation_approved_by": "VARCHAR(120)",
        "correlation_id": "INTEGER",
    }
    with engine.begin() as connection:
        if "status" not in incident_columns:
            connection.execute(
                text("ALTER TABLE incident_records ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'PENDING'")
            )
        for name, definition in incident_additions.items():
            if name not in incident_columns:
                connection.execute(
                    text(f"ALTER TABLE incident_records ADD COLUMN {name} {definition}")
                )
        for name, definition in additions.items():
            if name not in visitor_columns:
                connection.execute(
                    text(f"ALTER TABLE visitor_logs ADD COLUMN {name} {definition}")
                )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_incident_records_correlation_id ON incident_records (correlation_id)")
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_incident_records_created_at ON incident_records (created_at)")
        )
