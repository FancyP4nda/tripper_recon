from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProviderOutcome(str, Enum):
    """What happened when one provider was asked about one indicator.

    The distinction between ``NOT_CONFIGURED`` and ``OK`` is the point of this enum. A
    provider that was never asked because no credential exists produces no data, and so does a
    provider that was asked and found nothing -- but only one of those is evidence. Collapsing
    them is how "never asked" starts rendering as "came back clean".
    """

    #: The provider answered and its payload is in :attr:`ProviderCall.data`.
    OK = "ok"
    #: The call was made and failed. Details are in :attr:`ProviderCall.error`.
    ERROR = "error"
    #: No credential, so no request was made. Absence of data here means nothing at all.
    NOT_CONFIGURED = "not_configured"


class ProviderCall(BaseModel):
    """One provider call: what came back, whether it worked, and what it cost.

    Produced by ``orchestrators._call_provider`` for every outbound provider call in the
    package. It replaces the 23 copies of ``try / await / except`` that each flattened a
    failure into a bare ``{}`` at the data-assembly step.

    Fields deliberately kept apart:

    * :attr:`data` is populated only on :attr:`ProviderOutcome.OK`. It is the provider's own
      ``data`` sub-dict, unchanged, which is what the renderer consumes.
    * :attr:`error` is the redacted ``_error_payload`` with ``ok`` and null fields stripped.
      Every string in it has been through ``utils.redact``.
    * :attr:`summary` is the one-line form that lands in ``InvestigationResult.errors``.
    * :attr:`suppressed` records the ``_should_suppress`` decision at call time, so the
      rendering layer can choose to hide an expected failure without the data being discarded.
    """

    #: Label used for suppression and in the error summary; not always the output key.
    provider: str
    outcome: ProviderOutcome
    #: Wall-clock seconds spent awaiting this provider, including its internal retries.
    elapsed_seconds: float = Field(default=0.0, ge=0.0)
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Dict[str, Any] = Field(default_factory=dict)
    summary: str = Field(default="")
    suppressed: bool = Field(default=False)

    @property
    def ok(self) -> bool:
        return self.outcome is ProviderOutcome.OK


class ApiKeys(BaseModel):
    cloudflare_api_token: Optional[str] = Field(default=None)
    vt_api_key: Optional[str] = Field(default=None)
    shodan_api_key: Optional[str] = Field(default=None)
    abuseipdb_api_key: Optional[str] = Field(default=None)
    ipinfo_token: Optional[str] = Field(default=None)
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
