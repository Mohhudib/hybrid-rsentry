"""
schemas.py — SQLAlchemy ORM models (4 tables) + Pydantic request/response schemas.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Any, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, JSON, String, Text, Enum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field

from backend.models.database import Base


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventType(str, PyEnum):
    CANARY_TOUCHED = "CANARY_TOUCHED"
    ENTROPY_SPIKE = "ENTROPY_SPIKE"
    PROCESS_ANOMALY = "PROCESS_ANOMALY"
    COMBINED_ALERT = "COMBINED_ALERT"
    CONTAINMENT_TRIGGERED = "CONTAINMENT_TRIGGERED"
    CONTAINMENT_COMPLETE = "CONTAINMENT_COMPLETE"
    HEARTBEAT = "HEARTBEAT"


class Severity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class Host(Base):
    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(String(255), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_contained = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)

    events = relationship("Event", back_populates="host", lazy="dynamic")
    alerts = relationship("Alert", back_populates="host", lazy="dynamic")


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(String(255), ForeignKey("hosts.host_id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    event_type = Column(Enum(EventType), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    pid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=True)
    file_path = Column(Text, nullable=True)
    lineage_score = Column(Float, default=0.0)
    entropy_delta = Column(Float, default=0.0)
    canary_hit = Column(Boolean, default=False)
    details = Column(JSON, nullable=True)

    host = relationship("Host", back_populates="events")
    alert = relationship("Alert", back_populates="event", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False, unique=True)
    host_id = Column(String(255), ForeignKey("hosts.host_id"), nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False)
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    event = relationship("Event", back_populates="alert")
    host = relationship("Host", back_populates="alerts")
    evidence = relationship("Evidence", back_populates="alert", lazy="dynamic")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False, index=True)
    pid = Column(Integer, nullable=True)
    evidence_dir = Column(Text, nullable=True)
    files = Column(JSON, nullable=True)
    iptables_rule = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    captured_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert", back_populates="evidence")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class EventCreate(BaseModel):
    host_id: str
    timestamp: datetime
    event_type: EventType
    severity: Severity
    pid: int = 0
    process_name: str = ""
    file_path: str = ""
    lineage_score: float = Field(ge=0.0, le=100.0, default=0.0)
    entropy_delta: float = Field(ge=0.0, le=8.0, default=0.0)
    canary_hit: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    id: uuid.UUID
    host_id: str
    timestamp: datetime
    event_type: EventType
    severity: Severity
    pid: Optional[int] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    lineage_score: float
    entropy_delta: float
    canary_hit: bool
    details: Optional[dict[str, Any]]

    class Config:
        from_attributes = True


class AlertCreate(BaseModel):
    event_id: uuid.UUID
    host_id: str
    severity: Severity


class AlertResponse(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID
    host_id: str
    severity: Severity
    acknowledged: bool
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class EvidenceCreate(BaseModel):
    alert_id: uuid.UUID
    pid: Optional[int]
    evidence_dir: Optional[str]
    files: Optional[list[str]]
    iptables_rule: Optional[str]
    raw_data: Optional[dict[str, Any]]


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    pid: Optional[int]
    evidence_dir: Optional[str]
    files: Optional[list[str]]
    iptables_rule: Optional[str]
    captured_at: datetime

    class Config:
        from_attributes = True


class HostResponse(BaseModel):
    id: uuid.UUID
    host_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    last_seen: datetime
    is_contained: bool
    risk_score: float

    class Config:
        from_attributes = True
