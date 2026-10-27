from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, LargeBinary, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
    capture_data: Mapped["FlowData | None"] = relationship(lazy="selectin", uselist=False)

    @property
    def traffic_source(self):
        return "sample" if self.is_demo else self.capture_data.capture.source if self.capture_data else "pcap"

    @property
    def capture_id(self):
        return self.capture_data.capture_id if self.capture_data else None


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
    capture: Mapped["Capture"] = relationship(lazy="joined")


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


class LiveSession(Base):
    __tablename__ = "live_sessions"
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), primary_key=True)
    interface_id: Mapped[str] = mapped_column(String)
    interface_name: Mapped[str] = mapped_column(String)
    started_at: Mapped[str] = mapped_column(String)
    stopped_at: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String)
    error: Mapped[str] = mapped_column(Text, default="")
    counters_json: Mapped[str] = mapped_column(Text, default="{}")


class InspectionCapture(Base):
    __tablename__ = "inspection_captures"
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), primary_key=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_bytes_retained: Mapped[int] = mapped_column(Integer, default=0)


class TcpStream(Base):
    __tablename__ = "tcp_streams"
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), index=True)
    source: Mapped[str] = mapped_column(String)
    destination: Mapped[str] = mapped_column(String)
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)


class InspectionPacket(Base):
    __tablename__ = "inspection_packets"
    __table_args__ = (Index("ix_inspection_capture_number", "capture_id", "number", unique=True),)
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id"), index=True)
    flow_id: Mapped[int | None] = mapped_column(ForeignKey("flows.id"), nullable=True, index=True)
    stream_id: Mapped[int | None] = mapped_column(ForeignKey("tcp_streams.id"), nullable=True, index=True)
    number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String)
    destination: Mapped[str] = mapped_column(String)
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    transport: Mapped[str] = mapped_column(String)
    ip_version: Mapped[int] = mapped_column(Integer)
    length: Mapped[int] = mapped_column(Integer)
    captured_length: Mapped[int] = mapped_column(Integer)
    linktype: Mapped[int] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(String)
    direction: Mapped[str] = mapped_column(String, default="")
    tcp_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_ack: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_flags: Mapped[int] = mapped_column(Integer, default=0)
    payload_offset: Mapped[int] = mapped_column(Integer, default=0)
    payload_length: Mapped[int] = mapped_column(Integer, default=0)
    raw_status: Mapped[str] = mapped_column(String)
    warnings_json: Mapped[str] = mapped_column(Text, default="[]")


class PacketBytes(Base):
    __tablename__ = "packet_bytes"
    packet_id: Mapped[int] = mapped_column(ForeignKey("inspection_packets.id"), primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary)
