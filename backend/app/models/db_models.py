import os
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, JSON, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker

DATA = Path(os.environ.get('DATA_DIR', Path(__file__).resolve().parents[2] / 'data'))
DATA.mkdir(parents=True, exist_ok=True)
url = os.environ.get('DATABASE_URL', f'sqlite:///{DATA / "analysis.db"}')
engine = create_engine(url, pool_pre_ping=True, connect_args={'check_same_thread': False} if url.startswith('sqlite') else {})
DB = sessionmaker(bind=engine)
Base = declarative_base()


class Job(Base):
    __tablename__ = 'jobs'
    id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    report = Column(JSON)
    error = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RemoteCapture(Base):
    __tablename__ = 'remote_captures'
    id = Column(String, primary_key=True)


class JobOwner(Base):
    __tablename__ = 'job_owners'
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)


class LoginFlow(Base):
    __tablename__ = 'login_flows'
    id = Column(String, primary_key=True)
    verifier = Column(String, nullable=False)
    expires = Column(Float, nullable=False)


class UserSession(Base):
    __tablename__ = 'user_sessions'
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    email = Column(String, nullable=False)
    expires = Column(Float, nullable=False)
