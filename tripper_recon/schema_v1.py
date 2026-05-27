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


def _provider_statuses(
    result: InvestigationResult,
    *,
    provider_names: list[str] | tuple[str, ...] | None = None,
    extra_statuses: list[ProviderStatus] | tuple[ProviderStatus, ...] | None = None,
) -> list[ProviderStatus]:
    providers = provider_names or ["ipinfo", "virustotal", "shodan", "abuseipdb", "otx"]
    data = result.data or {}
    provider_errors = data.get("errors") if isinstance(data.get("errors"), dict) else {}
    statuses: list[ProviderStatus] = list(extra_statuses or [])

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


def _domain_provider_statuses(
    result: InvestigationResult,
    *,
    provider_names: list[str] | tuple[str, ...] | None = None,
    extra_statuses: list[ProviderStatus] | tuple[ProviderStatus, ...] | None = None,
) -> list[ProviderStatus]:
    providers = provider_names or ["virustotal", "otx"]
    data = result.data or {}
    domain_intel = data.get("domain_intel") if isinstance(data.get("domain_intel"), dict) else {}
    domain_errors = data.get("domain_errors") if isinstance(data.get("domain_errors"), dict) else {}
    statuses: list[ProviderStatus] = list(extra_statuses or [])

    for provider in providers:
        if provider == "local_dns":
            resolver_payload = data.get("resolver") if isinstance(data.get("resolver"), dict) else {}
            if resolver_payload:
                statuses.append(ProviderStatus(provider=provider, status="completed"))
            else:
                statuses.append(
                    ProviderStatus(
                        provider=provider,
                        status="missing_credentials",
                        reason="Resolver did not return domain data.",
                    )
                )
            continue
        payload = domain_intel.get(provider)
        if payload:
            statuses.append(ProviderStatus(provider=provider, status="completed"))
        elif provider in domain_errors:
            statuses.append(
                ProviderStatus(
                    provider=provider,
                    status="failed",
                    reason=str(domain_errors[provider]),
                )
            )
        else:
            statuses.append(
                ProviderStatus(
                    provider=provider,
                    status="missing_credentials",
                    reason="No provider data returned by legacy domain investigation.",
                )
            )
    return statuses


def _domain_evidence(result: InvestigationResult) -> list[Evidence]:
    evidence: list[Evidence] = []
    data = result.data or {}
    domain_intel = data.get("domain_intel") if isinstance(data.get("domain_intel"), dict) else {}
    for provider, payload in domain_intel.items():
        if not payload:
            continue
        evidence.append(
            Evidence(
                id=f"domain-{provider}-summary",
                provider=provider,
                evidence_class="reputation",
                summary=f"{provider} returned domain observation data.",
                data=payload if isinstance(payload, dict) else {"value": payload},
            )
        )
    for item in data.get("ips", []) or []:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        relationship_source = str(item.get("relationship_source") or "provider_observation")
        relationship_label = "analyst resolver" if relationship_source == "analyst_resolver" else "passive provider"
        evidence.append(
            Evidence(
                id=f"domain-{relationship_source}-ip-{ip}",
                provider=relationship_source,
                evidence_class="relationship",
                summary=f"Domain has {relationship_label} relationship to IP {ip}.",
                data={
                    "ip": ip,
                    "ptr": item.get("ptr"),
                    "relationship_source": relationship_source,
                    "also_seen_in_provider_observations": bool(item.get("also_seen_in_provider_observations")),
                },
            )
        )
    return evidence


def _domain_relationships(result: InvestigationResult) -> list[Relationship]:
    relationships: list[Relationship] = []
    data = result.data or {}
    domain = str(data.get("domain") or "")
    for item in data.get("ips", []) or []:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        relationship_source = str(item.get("relationship_source") or "provider_observation")
        evidence_id = f"domain-{relationship_source}-ip-{ip}"
        relationships.append(
            Relationship(
                id=f"{domain}-resolves-to-{ip}",
                source=domain,
                target=str(ip),
                relationship_type="analyst_resolver_dns" if relationship_source == "analyst_resolver" else "passive_dns_a_or_aaaa",
                evidence_ids=[evidence_id],
            )
        )
    return relationships


def ip_result_to_schema_v1(
    *,
    target: str,
    result: InvestigationResult,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_names: list[str] | tuple[str, ...] | None = None,
    extra_provider_statuses: list[ProviderStatus] | tuple[ProviderStatus, ...] | None = None,
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
        provider_status=_provider_statuses(
            result,
            provider_names=provider_names,
            extra_statuses=extra_provider_statuses,
        )
        if result.ok
        else list(extra_provider_statuses or []),
        evidence=_ip_evidence(result) if result.ok else [],
        errors=list(result.errors),
        warnings=list(result.warnings),
    )


def failed_ip_result_v1(
    *,
    target: str,
    error: str,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_status: ProviderStatus | None = None,
) -> InvestigationResultV1:
    return InvestigationResultV1(
        target_type="ip",
        input=target,
        normalized_target=target,
        mode=mode,
        profile=profile,
        execution_status="failed",
        provider_status=[provider_status] if provider_status else [],
        errors=[error],
    )


def domain_result_to_schema_v1(
    *,
    target: str,
    normalized_target: str,
    result: InvestigationResult,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_names: list[str] | tuple[str, ...] | None = None,
    extra_provider_statuses: list[ProviderStatus] | tuple[ProviderStatus, ...] | None = None,
) -> InvestigationResultV1:
    execution_status: ExecutionStatus
    if result.ok and result.errors:
        execution_status = "partial"
    elif result.ok:
        execution_status = "completed"
    else:
        execution_status = "failed"

    return InvestigationResultV1(
        target_type="domain",
        input=target,
        normalized_target=normalized_target,
        mode=mode,
        profile=profile,
        execution_status=execution_status,
        provider_status=_domain_provider_statuses(
            result,
            provider_names=provider_names,
            extra_statuses=extra_provider_statuses,
        )
        if result.ok
        else list(extra_provider_statuses or []),
        evidence=_domain_evidence(result) if result.ok else [],
        relationships=_domain_relationships(result) if result.ok else [],
        errors=list(result.errors),
        warnings=list(result.warnings),
    )


def failed_domain_result_v1(
    *,
    target: str,
    normalized_target: str,
    error: str,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_status: ProviderStatus | None = None,
) -> InvestigationResultV1:
    return InvestigationResultV1(
        target_type="domain",
        input=target,
        normalized_target=normalized_target,
        mode=mode,
        profile=profile,
        execution_status="failed",
        provider_status=[provider_status] if provider_status else [],
        errors=[error],
    )


def failed_result_v1(
    *,
    target_type: TargetType,
    target: str,
    normalized_target: str,
    error: str,
    mode: str = "passive",
    profile: str = "best_effort",
) -> InvestigationResultV1:
    return InvestigationResultV1(
        target_type=target_type,
        input=target,
        normalized_target=normalized_target,
        mode=mode,
        profile=profile,
        execution_status="failed",
        errors=[error],
    )
