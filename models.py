import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, BigInteger, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DB_PATH = os.getenv("DB_PATH", "/data/panel.db")
try:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    open(DB_PATH, "a").close()
except OSError:
    DB_PATH = "./panel.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True)
    remark = Column(String, nullable=False)
    kind = Column(String, nullable=False)  # web-http | edge-tcp | edge-http
    mode = Column(String, default="packet-up")
    path = Column(String, default="/s/")
    key_a = Column(String, default="")
    key_b = Column(String, default="")
    tag_id = Column(String, default="")
    enable = Column(Boolean, default=True)
    clients = relationship("Account", back_populates="endpoint", cascade="all, delete-orphan")


class Account(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=False)
    name = Column(String, nullable=False)
    uuid = Column(String, nullable=False)
    sub_token = Column(String, unique=True, nullable=False)
    total_bytes = Column(BigInteger, default=0)  # 0 = unlimited
    used_bytes = Column(BigInteger, default=0)
    expiry = Column(DateTime, nullable=True)  # UTC, None = never
    enable = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    endpoint = relationship("Endpoint", back_populates="clients")
