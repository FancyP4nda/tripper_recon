from __future__ import annotations

from dataclasses import dataclass

from tripper_recon.schema_v1 import InvestigationResultV1, TargetType


@dataclass(frozen=True)
class CoverageRequirement:
    name: str
    providers: frozenset[str] = frozenset()
    evidence_classes: frozenset[str] = frozenset()
    relationship_types: frozenset[str] = frozenset()


CISO_DAILY_POLICY: dict[TargetType, tuple[CoverageRequirement, ...]] = {
    "ip": (
        CoverageRequirement("ip_reputation", providers=frozenset({"virustotal", "abuseipdb", "otx"})),
        CoverageRequirement("ip_context", providers=frozenset({"ipinfo", "shodan", "asn_meta", "cloudflare_asn"})),
    ),
    "domain": (
        CoverageRequirement("domain_reputation", providers=frozenset({"virustotal", "otx"})),
        CoverageRequirement(
            "domain_relationship",
            evidence_classes=frozenset({"relationship"}),
            relationship_types=frozenset({"passive_dns_a_or_aaaa", "analyst_resolver_dns"}),
        ),
    ),
    "url": (
        CoverageRequirement("url_parser_relationship", providers=frozenset({"url_parser"})),
        CoverageRequirement("url_reputation", providers=frozenset({"virustotal", "otx"})),
    ),
    "asn": (
        CoverageRequirement("asn_context", providers=frozenset({"ipinfo", "cloudflare_asn"})),
    ),
}


def missing_ciso_daily_requirements(result: InvestigationResultV1) -> list[str]:
    requirements = CISO_DAILY_POLICY.get(result.target_type, ())
    completed_providers = {
        status.provider for status in result.provider_status if status.status == "completed"
    }
    evidence_providers = {item.provider for item in result.evidence}
    evidence_classes = {item.evidence_class for item in result.evidence}
    relationship_types = {item.relationship_type for item in result.relationships}

    missing: list[str] = []
    for requirement in requirements:
        provider_ok = not requirement.providers or bool(
            requirement.providers & completed_providers or requirement.providers & evidence_providers
        )
        evidence_ok = not requirement.evidence_classes or bool(requirement.evidence_classes & evidence_classes)
        relationship_ok = not requirement.relationship_types or bool(requirement.relationship_types & relationship_types)
        if not (provider_ok and evidence_ok and relationship_ok):
            missing.append(requirement.name)
    return missing


def apply_profile_completeness(
    result: InvestigationResultV1,
    *,
    require_profile_complete: bool,
) -> InvestigationResultV1:
    if result.profile != "ciso_daily":
        return result
    missing = missing_ciso_daily_requirements(result)
    if not missing:
        return result
    message = "profile_incomplete:ciso_daily missing " + ", ".join(missing)
    result.warnings.append(message)
    if require_profile_complete:
        result.execution_status = "failed"
        result.errors.append(message)
    elif result.execution_status == "completed":
        result.execution_status = "partial"
    return result

