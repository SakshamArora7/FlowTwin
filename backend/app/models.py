from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Flow(Base):
    __tablename__ = "flows"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    destination: Mapped[str] = mapped_column(String)
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    packets: Mapped[int] = mapped_column(Integer)
    bytes: Mapped[int] = mapped_column(Integer)
    duration_ms: Mapped[float] = mapped_column(Float)
    classification: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=True)


class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    demo_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    refresh_seconds: Mapped[int] = mapped_column(Integer, default=30)


class Capture(Base):
    __tablename__ = "captures"
    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String)
    imported_at: Mapped[str] = mapped_column(String)
    packet_count: Mapped[int] = mapped_column(Integer)
    flow_count: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String, default="pcap")


class FlowData(Base):
    __tablename__ = "flow_data"
    flow_id: Mapped[int] = mapped_column(ForeignKey("flows.id"), primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), index=True)
    features_json: Mapped[str] = mapped_column(Text)
    explanation_json: Mapped[str] = mapped_column(Text, default="[]")


class PacketRecord(Base):
    __tablename__ = "packets"
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), index=True)
    flow_id: Mapped[int] = mapped_column(ForeignKey("flows.id"), index=True)
    timestamp: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    destination: Mapped[str] = mapped_column(String)
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    size: Mapped[int] = mapped_column(Integer)
    flags: Mapped[str] = mapped_column(String, default="")
    direction: Mapped[str] = mapped_column(String)


class Detection(Base):
    __tablename__ = "detections"
    id: Mapped[int] = mapped_column(primary_key=True)
    flow_id: Mapped[int] = mapped_column(ForeignKey("flows.id"), unique=True, index=True)
    timestamp: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String)
    model_version: Mapped[str] = mapped_column(String)
    explanation_json: Mapped[str] = mapped_column(Text)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String, default="New")
