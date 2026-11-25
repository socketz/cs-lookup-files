from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class IpRecord(BaseModel):
    """Schema of a row in ``malicious_ips`` (used for validation/tests)."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    asn: int | None = None
    asn_name: str | None = None
    country: str | None = None
    confidence_score: int = Field(ge=0, le=100)
    source_count: int = Field(ge=0)
    sources: str
    categories: str
    first_seen: str
    last_seen: str


class NetworkRecord(BaseModel):
    """Schema of a row in ``malicious_networks``."""

    model_config = ConfigDict(extra="forbid")

    network: str
    asn: int | None = None
    asn_name: str | None = None
    confidence_score: int = Field(ge=0, le=100)
    source_count: int = Field(ge=0)
    sources: str
    categories: str


class AsnRecord(BaseModel):
    """Schema of a row in ``malicious_asns`` (authoritative ASN lists only)."""

    model_config = ConfigDict(extra="forbid")

    asn: int
    asn_name: str | None = None
    country: str | None = None
    confidence_score: int = Field(ge=0, le=100)
    source_count: int = Field(ge=0)
    sources: str
    categories: str
    first_seen: str
    last_seen: str
