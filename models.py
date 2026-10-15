from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, BigInteger, Integer, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Admin(Base):
    __tablename__ = "admins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    proxy_ip: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port_start: Mapped[int] = mapped_column(Integer, default=20000, nullable=False)
    port_end: Mapped[int] = mapped_column(Integer, default=20100, nullable=False)
    agent_url: Mapped[str] = mapped_column(String(512), nullable=False)
    agent_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    tls_sni: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_cert_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tls_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reality_sni: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reality_private_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    reality_public_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reality_short_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    clients: Mapped[list["Client"]] = relationship(back_populates="node")

class Client(Base):
    __tablename__ = "clients"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    transport: Mapped[str] = mapped_column(String(20), nullable=False)
    security: Mapped[str] = mapped_column(String(20), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="RESTRICT"), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    inbound_tag: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    credential_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    inbound_json_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    subscription_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    subscription_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    node: Mapped[Node] = relationship(back_populates="clients")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

Index("ix_clients_node_port", Client.node_id, Client.port, unique=True)
