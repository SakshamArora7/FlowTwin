from pydantic import BaseModel, ConfigDict, Field


class SettingsSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, strict=True)
    demo_mode: bool
    refresh_seconds: int = Field(ge=10, le=300)


class FlowSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: str
    source: str
    destination: str
    source_port: int
    destination_port: int
    protocol: str
    packets: int
    bytes: int
    duration_ms: float
    classification: str
    category: str
    is_demo: bool
    traffic_source: str
    capture_id: int | None
