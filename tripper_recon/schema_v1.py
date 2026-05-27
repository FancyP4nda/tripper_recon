from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, Field

from tripper_recon.types.models import InvestigationResult


SCHEMA_VERSION = "1.0"
RAW_PAYLOAD_MAX_BYTES = 4096
REDACTED = "[REDACTED]"

TargetType = Literal["ip", "domain", "url", "asn"]
ExecutionStatus = Literal["completed", "partial", "failed"]
Verdict = Literal["malicious", "suspicious", "benign_contextual", "unknown"]
SENSITIVE_KEYS = {"token", "key", "api_key", "apikey", "authorization", "x-api-key"}
HEADER_KEYS = {"headers", "request_headers", "requestheaders"}


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


def _sanitize_url(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc or not parsed.query:
        return value
    query = [
        (key, REDACTED if key.lower() in SENSITIVE_KEYS else val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, safe="[]"), parsed.fragment))


def _sanitize_for_output(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if key_lower in HEADER_KEYS:
                continue
            if key_lower in SENSITIVE_KEYS:
                clean[key_text] = REDACTED
            else:
                clean[key_text] = _sanitize_for_output(item)
        return clean
    if isinstance(value, list):
        return [_sanitize_for_output(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_for_output(item) for item in value]
    if isinstance(value, str):
        return _sanitize_url(value)
    return value


def _sanitize_reason(value: Any) -> str:
    return str(_sanitize_for_output(value))


def _raw_payload_data(payload: Any, *, max_bytes: int = RAW_PAYLOAD_MAX_BYTES) -> dict[str, Any]:
    sanitized = _sanitize_for_output(payload)
    encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str)
    original_size = len(encoded.encode("utf-8"))
    if original_size <= max_bytes:
        return {
            "raw": sanitized,
            "raw_truncated": False,
            "raw_original_size_bytes": original_size,
            "raw_emitted_size_bytes": original_size,
            "raw_max_size_bytes": max_bytes,
        }

    truncated = encoded.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
    emitted_size = len(truncated.encode("utf-8"))
    return {
        "raw": truncated,
        "raw_truncated": True,
        "raw_original_size_bytes": original_size,
        "raw_emitted_size_bytes": emitted_size,
        "raw_max_size_bytes": max_bytes,
    }


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _severity(value: int) -> Literal["none", "low", "medium", "high", "critical"]:
    if value >= 90:
        return "critical"
    if value >= 70:
        return "high"
    if value >= 40:
        return "medium"
    if value > 0:
        return "low"
    return "none"


def _verdict(value: int, *, has_reputation_support: bool, has_contextual_support: bool) -> Verdict:
    if has_reputation_support and value >= 70:
        return "malicious"
    if has_reputation_support and value >= 30:
        return "suspicious"
    if has_contextual_support and value > 0:
        return "benign_contextual"
    return "unknown"


def _confidence(value: int, reason_count: int) -> float:
    if value <= 0 or reason_count <= 0:
        return 0.0
    return min(1.0, round(0.35 + (0.15 * reason_count) + (0.2 if value >= 70 else 0.0), 2))


def _evidence_ids_by_provider(evidence: list[Evidence]) -> dict[str, str]:
    return {item.provider: item.id for item in evidence}


def _score_from_ip_data(data: dict[str, Any], evidence: list[Evidence]) -> tuple[Score, Verdict, float]:
    evidence_ids = _evidence_ids_by_provider(evidence)
    scores: list[int] = []
    reasons: list[str] = []
    reputation_support = False
    contextual_support = False

    vt = data.get("virustotal") if isinstance(data.get("virustotal"), dict) else {}
    vt_evidence_id = evidence_ids.get("virustotal")
    if vt and vt_evidence_id:
        stats = vt.get("vt_last_analysis_stats") if isinstance(vt.get("vt_last_analysis_stats"), dict) else {}
        malicious = _as_int(stats.get("malicious"))
        reputation = _as_int(vt.get("vt_reputation"))
        if malicious > 0:
            reputation_support = True
            scores.append(min(90, 50 + (malicious * 5)))
            reasons.append(f"{vt_evidence_id}: VirusTotal reported {malicious} malicious detections.")
        elif reputation <= -10:
            reputation_support = True
            scores.append(40)
            reasons.append(f"{vt_evidence_id}: VirusTotal community reputation is {reputation}.")

    abuse = data.get("abuseipdb") if isinstance(data.get("abuseipdb"), dict) else {}
    abuse_evidence_id = evidence_ids.get("abuseipdb")
    if abuse and abuse_evidence_id:
        confidence_score = _as_int(abuse.get("abuseipdb_confidence_score"))
        if confidence_score >= 75:
            reputation_support = True
            scores.append(80)
            reasons.append(f"{abuse_evidence_id}: AbuseIPDB confidence score is {confidence_score}.")
        elif confidence_score >= 25:
            reputation_support = True
            scores.append(45)
            reasons.append(f"{abuse_evidence_id}: AbuseIPDB confidence score is {confidence_score}.")

    otx = data.get("otx") if isinstance(data.get("otx"), dict) else {}
    otx_evidence_id = evidence_ids.get("otx")
    if otx and otx_evidence_id:
        pulse_count = _as_int(otx.get("otx_pulse_count"))
        if pulse_count >= 10:
            reputation_support = True
            scores.append(60)
            reasons.append(f"{otx_evidence_id}: OTX reported {pulse_count} pulses.")
        elif pulse_count > 0:
            reputation_support = True
            scores.append(35)
            reasons.append(f"{otx_evidence_id}: OTX reported {pulse_count} pulses.")

    for provider in ("ipinfo", "shodan", "asn_meta"):
        if data.get(provider) and evidence_ids.get(provider):
            contextual_support = True
            scores.append(15)
            reasons.append(f"{evidence_ids[provider]}: {provider} returned context evidence.")

    value = max(scores, default=0)
    return (
        Score(severity=_severity(value), value=value, reasons=reasons),
        _verdict(value, has_reputation_support=reputation_support, has_contextual_support=contextual_support),
        _confidence(value, len(reasons)),
    )


def _score_from_domain_data(data: dict[str, Any], evidence: list[Evidence]) -> tuple[Score, Verdict, float]:
    evidence_ids = _evidence_ids_by_provider(evidence)
    scores: list[int] = []
    reasons: list[str] = []
    reputation_support = False
    contextual_support = False
    domain_intel = data.get("domain_intel") if isinstance(data.get("domain_intel"), dict) else {}

    vt = domain_intel.get("virustotal") if isinstance(domain_intel.get("virustotal"), dict) else {}
    vt_evidence_id = evidence_ids.get("virustotal")
    if vt and vt_evidence_id:
        stats = vt.get("vt_last_analysis_stats") if isinstance(vt.get("vt_last_analysis_stats"), dict) else {}
        malicious = _as_int(stats.get("malicious"))
        reputation = _as_int(vt.get("vt_reputation"))
        if malicious > 0:
            reputation_support = True
            scores.append(min(90, 50 + (malicious * 5)))
            reasons.append(f"{vt_evidence_id}: VirusTotal reported {malicious} malicious detections.")
        elif reputation <= -10:
            reputation_support = True
            scores.append(40)
            reasons.append(f"{vt_evidence_id}: VirusTotal community reputation is {reputation}.")

    otx = domain_intel.get("otx") if isinstance(domain_intel.get("otx"), dict) else {}
    otx_evidence_id = evidence_ids.get("otx")
    if otx and otx_evidence_id:
        pulse_count = _as_int(otx.get("otx_pulse_count"))
        if pulse_count >= 10:
            reputation_support = True
            scores.append(60)
            reasons.append(f"{otx_evidence_id}: OTX reported {pulse_count} pulses.")
        elif pulse_count > 0:
            reputation_support = True
            scores.append(35)
            reasons.append(f"{otx_evidence_id}: OTX reported {pulse_count} pulses.")

    relationship_ids = [item.id for item in evidence if item.evidence_class == "relationship"]
    if relationship_ids:
        contextual_support = True
        scores.append(15)
        reasons.extend(f"{evidence_id}: Domain relationship evidence is present." for evidence_id in relationship_ids)

    value = max(scores, default=0)
    return (
        Score(severity=_severity(value), value=value, reasons=reasons),
        _verdict(value, has_reputation_support=reputation_support, has_contextual_support=contextual_support),
        _confidence(value, len(reasons)),
    )


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
                    reason=_sanitize_reason(provider_errors[provider]),
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


def _ip_evidence(result: InvestigationResult, *, include_raw: bool = False) -> list[Evidence]:
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
                data=_raw_payload_data(payload) if include_raw else {},
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
                    reason=_sanitize_reason(domain_errors[provider]),
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


def _domain_evidence(result: InvestigationResult, *, include_raw: bool = False) -> list[Evidence]:
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
                data=_raw_payload_data(payload) if include_raw else {},
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
    include_raw: bool = False,
) -> InvestigationResultV1:
    execution_status: ExecutionStatus
    if result.ok and result.errors:
        execution_status = "partial"
    elif result.ok:
        execution_status = "completed"
    else:
        execution_status = "failed"
    evidence = _ip_evidence(result, include_raw=include_raw) if result.ok else []
    score, verdict, confidence = _score_from_ip_data(result.data or {}, evidence) if result.ok else (Score(), "unknown", 0.0)

    return InvestigationResultV1(
        target_type="ip",
        input=target,
        normalized_target=target,
        mode=mode,
        profile=profile,
        execution_status=execution_status,
        verdict=verdict,
        score=score,
        confidence=confidence,
        provider_status=_provider_statuses(
            result,
            provider_names=provider_names,
            extra_statuses=extra_provider_statuses,
        )
        if result.ok
        else list(extra_provider_statuses or []),
        evidence=evidence,
        errors=[_sanitize_reason(error) for error in result.errors],
        warnings=[_sanitize_reason(warning) for warning in result.warnings],
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
    include_raw: bool = False,
) -> InvestigationResultV1:
    execution_status: ExecutionStatus
    if result.ok and result.errors:
        execution_status = "partial"
    elif result.ok:
        execution_status = "completed"
    else:
        execution_status = "failed"
    evidence = _domain_evidence(result, include_raw=include_raw) if result.ok else []
    score, verdict, confidence = _score_from_domain_data(result.data or {}, evidence) if result.ok else (Score(), "unknown", 0.0)

    return InvestigationResultV1(
        target_type="domain",
        input=target,
        normalized_target=normalized_target,
        mode=mode,
        profile=profile,
        execution_status=execution_status,
        verdict=verdict,
        score=score,
        confidence=confidence,
        provider_status=_domain_provider_statuses(
            result,
            provider_names=provider_names,
            extra_statuses=extra_provider_statuses,
        )
        if result.ok
        else list(extra_provider_statuses or []),
        evidence=evidence,
        relationships=_domain_relationships(result) if result.ok else [],
        errors=[_sanitize_reason(error) for error in result.errors],
        warnings=[_sanitize_reason(warning) for warning in result.warnings],
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


def url_result_to_schema_v1(
    *,
    target: str,
    normalized_target: str,
    extracted_domain: str,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_statuses: list[ProviderStatus] | tuple[ProviderStatus, ...] | None = None,
) -> InvestigationResultV1:
    evidence_id = "url-parser-domain"
    return InvestigationResultV1(
        target_type="url",
        input=target,
        normalized_target=normalized_target,
        mode=mode,
        profile=profile,
        execution_status="completed",
        verdict="unknown",
        provider_status=list(provider_statuses or []),
        evidence=[
            Evidence(
                id=evidence_id,
                provider="url_parser",
                evidence_class="relationship",
                summary=f"URL contains domain {extracted_domain}.",
                data={"domain": extracted_domain},
            )
        ],
        relationships=[
            Relationship(
                id=f"{normalized_target}-contains-domain-{extracted_domain}",
                source=normalized_target,
                target=extracted_domain,
                relationship_type="url_contains_domain",
                evidence_ids=[evidence_id],
            )
        ],
    )


def failed_url_result_v1(
    *,
    target: str,
    normalized_target: str,
    error: str,
    mode: str = "passive",
    profile: str = "best_effort",
    provider_status: ProviderStatus | None = None,
) -> InvestigationResultV1:
    return InvestigationResultV1(
        target_type="url",
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
