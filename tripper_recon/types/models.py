from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ApiKeys(BaseModel):
    cloudflare_api_token: Optional[str] = Field(default=None)
    vt_api_key: Optional[str] = Field(default=None)
    shodan_api_key: Optional[str] = Field(default=None)
    abuseipdb_api_key: Optional[str] = Field(default=None)
    ipapi_is_api_key: Optional[str] = Field(default=None)
    otx_api_key: Optional[str] = Field(default=None)


class Settings(BaseModel):
    timeout_seconds: float = Field(default=15.0)
    rate_limit: int = Field(default=5)
    api_keys: ApiKeys = Field(default_factory=ApiKeys)


class IPQuery(BaseModel):
    ip: str


class DomainQuery(BaseModel):
    domain: str


class ASNQuery(BaseModel):
    asn: int


class InvestigationResult(BaseModel):
    ok: bool
    data: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


