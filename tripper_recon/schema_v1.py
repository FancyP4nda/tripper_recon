from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from tripper_recon.types.models import InvestigationResult


SCHEMA_VERSION = "1.0"

TargetType = Literal["ip", "domain", "url", "asn"]
ExecutionStatus = Literal["completed", "partial", "failed"]
Verdict = Literal["malicious", "suspicious", "benign_contextual", "unknown"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    evidence_ids: list[str] = Field(default_factory=list)


class Relationship(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    evidence_ids: list[str] = Field(default_factory=list)


class ProviderStatus(BaseModel):
    provider: str
    status: Literal["completed", "partial", "skipped", "failed", "missing_credentials"]
    reason: str | None = None


class Evidence(BaseModel):
    id: str
    provider: str
    evidence_class: Literal["reputation", "context", "relationship"]
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)


class CacheInfo(BaseModel):
    hit: bool = False
    provider: str | None = None
    retrieved_at: str | None = None
    observed_at: str | None = None


class Score(BaseModel):
    severity: Literal["none", "low", "medium", "high", "critical"] = "none"
    value: int = Field(default=0, ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)


class InvestigationResultV1(BaseModel):
    schema_version: str = SCHEMA_VERSION
    target_type: TargetType
    input: str
    normalized_target: str
    mode: str = "passive"
    profile: str = "best_effort"
    execution_status: ExecutionStatus
    verdict: Verdict = "unknown"
    score: Score = Field(default_factory=Score)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    provider_status: list[ProviderStatus] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    cache: list[CacheInfo] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _provider_statuses(result: InvestigationResult) -> list[ProviderStatus]:
    providers = ["ipinfo", "virustotal", "shodan", "abuseipdb", "otx"]
    data = result.data or {}
    provider_errors = data.get("errors") if isinstance(data.get("errors"), dict) else {}
    statuses: list[ProviderStatus] = []

    for provider in providers:
        payload = data.get(provider)
        if payload:
            statuses.append(ProviderStatus(provider=provider, status="completed"))
        elif provider in provider_errors:
            statuses.append(
                ProviderStatus(
                    provider=provider,
                    status="failed",
                    reason=str(provider_errors[provider]),
                )
            )
        else:
            statuses.append(
                ProviderStatus(
                    provider=provider,
                    status="missing_credentials",
                    reason="No provider data returned by legacy IP investigation.",
                )
            )
    return statuses


def _ip_evidence(result: InvestigationResult) -> list[Evidence]:
    evidence: list[Evidence] = []
    data = result.data or {}
    for provider in ("ipinfo", "virustotal", "shodan", "abuseipdb", "otx", "asn_meta"):
        payload = data.get(provider)
        if not payload:
            continue
        evidence.append(
            Evidence(
                id=f"{provider}-summary",
                provider=provider,
                evidence_class="context" if provider in {"ipinfo", "asn_meta"} else "reputation",
                summary=f"{provider} returned observation data.",
                data=payload if isinstance(payload, dict) else {"value": payload},
            )
        )
    return evidence


def ip_result_to_schema_v1(
    *,
    target: str,
    result: InvestigationResult,
    mode: str = "passive",
    profile: str = "best_effort",
) -> InvestigationResultV1:
    execution_status: ExecutionStatus
    if result.ok and result.errors:
        execution_status = "partial"
    elif result.ok:
        execution_status = "completed"
    else:
        execution_status = "failed"

    return InvestigationResultV1(
        target_type="ip",
        input=target,
        normalized_target=target,
        mode=mode,
        profile=profile,
        execution_status=execution_status,
        provider_status=_provider_statuses(result) if result.ok else [],
        evidence=_ip_evidence(result) if result.ok else [],
        errors=list(result.errors),
        warnings=list(result.warnings),
    )

