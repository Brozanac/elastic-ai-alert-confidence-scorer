from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FlexibleModel(BaseModel):
    """
    Allows extra Elastic/ECS fields without breaking validation.

    Elastic alerts can contain many fields that this project does not use yet.
    We validate the fields we care about, but allow extra fields to pass through.
    """

    model_config = ConfigDict(extra="allow")


class Rule(FlexibleModel):
    name: str | None = Field(default=None, max_length=200)
    severity: str | None = Field(default=None, max_length=30)
    risk_score: int | None = Field(default=None, ge=0, le=100)


class HostOS(FlexibleModel):
    type: str | None = Field(default=None, max_length=50)
    name: str | None = Field(default=None, max_length=100)


class Host(FlexibleModel):
    name: str | None = Field(default=None, max_length=150)
    os: HostOS | None = None


class User(FlexibleModel):
    name: str | None = Field(default=None, max_length=150)
    id: str | None = Field(default=None, max_length=150)


class ProcessParent(FlexibleModel):
    name: str | None = Field(default=None, max_length=150)
    command_line: str | None = Field(default=None, max_length=5000)


class Process(FlexibleModel):
    name: str | None = Field(default=None, max_length=150)
    command_line: str | None = Field(default=None, max_length=5000)
    parent: ProcessParent | None = None


class Event(FlexibleModel):
    category: list[str] | None = None
    action: str | None = Field(default=None, max_length=150)
    outcome: str | None = Field(default=None, max_length=150)
    created: str | None = Field(default=None, max_length=100)

    @field_validator("category")
    @classmethod
    def validate_category_size(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value

        if len(value) > 20:
            raise ValueError("event.category cannot contain more than 20 values")

        return value


class Source(FlexibleModel):
    ip: str | None = Field(default=None, max_length=100)
    port: int | None = Field(default=None, ge=0, le=65535)


class Destination(FlexibleModel):
    ip: str | None = Field(default=None, max_length=100)
    port: int | None = Field(default=None, ge=0, le=65535)


class Network(FlexibleModel):
    protocol: str | None = Field(default=None, max_length=50)
    direction: str | None = Field(default=None, max_length=50)


class FileHash(FlexibleModel):
    sha256: str | None = Field(default=None, max_length=64)
    md5: str | None = Field(default=None, max_length=32)


class File(FlexibleModel):
    name: str | None = Field(default=None, max_length=255)
    path: str | None = Field(default=None, max_length=1000)
    hash: FileHash | None = None


class AlertRequest(FlexibleModel):
    rule: Rule | None = None
    host: Host | None = None
    user: User | None = None
    process: Process | None = None
    event: Event | None = None
    source: Source | None = None
    destination: Destination | None = None
    network: Network | None = None
    file: File | None = None

    @field_validator("rule", "host", "user", "process", "event", "source", "destination", "network", "file", mode="before")
    @classmethod
    def top_level_fields_must_be_objects(cls, value: Any) -> Any:
        if value is None:
            return value

        if not isinstance(value, dict):
            raise ValueError("Top-level alert sections must be JSON objects")

        return value