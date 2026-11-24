from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IndicatorState(BaseModel):
    """Persisted observation history for one IP, network or other IOC."""

    model_config = ConfigDict(extra="forbid")

    type: str  # indicator type: ip | network | domain | md5 | sha256
    value: str  # display value (IP address, canonical CIDR, domain, hash)
    first_seen: datetime
    last_seen: datetime
    sources: dict[str, int] = Field(default_factory=dict)


class State(BaseModel):
    """``state.json``: observation history merged across runs.

    Keys are ``str(ip_int)`` for IP indicators and the canonical network CIDR
    for networks. No collision is possible because networks always contain ``/``.
    """

    model_config = ConfigDict(extra="forbid")

    version: str = "1"
    generated_at: datetime = Field(default_factory=lambda: datetime.now())
    url: str | None = None
    indicators: dict[str, IndicatorState] = Field(default_factory=dict)
