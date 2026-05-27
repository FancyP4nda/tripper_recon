from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from tripper_recon.orchestrators import investigate_domain, investigate_ip
from tripper_recon.provider_registry import ProviderSelectionError, select_providers
from tripper_recon.schema_v1 import (
    InvestigationResultV1,
    ProviderStatus,
    domain_result_to_schema_v1,
    failed_domain_result_v1,
    failed_ip_result_v1,
    failed_url_result_v1,
    failed_result_v1,
    ip_result_to_schema_v1,
    url_result_to_schema_v1,
)
from tripper_recon.utils.validation import is_valid_asn, is_valid_domain, is_valid_ip


@dataclass(frozen=True)
class InvestigationOptions:
    mode: str = "passive"
    profile: str = "best_effort"
    providers: tuple[str, ...] | None = None
    include_raw: bool = False
    require_profile_complete: bool = False
    cache: bool = True


def normalize_provider_param(value: str | list[str] | tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        providers = [item.strip() for item in value.split(",")]
    else:
        providers = []
        for item in value:
            providers.extend(part.strip() for part in str(item).split(","))
    clean = tuple(item for item in providers if item)
    return clean or None


def classify_target(value: str) -> tuple[str, str]:
    stripped = value.strip()
    parsed = urlparse(stripped)
    if is_valid_ip(stripped):
        return "ip", stripped
    if parsed.scheme and parsed.netloc:
        return "url", stripped
    if is_valid_domain(stripped):
        return "domain", stripped
    asn_candidate = stripped[2:] if stripped.lower().startswith("as") else stripped
    if is_valid_asn(asn_candidate):
        return "asn", asn_candidate
    return "domain", stripped


def validate_typed_target(expected_type: str, value: str) -> tuple[bool, str, str | None]:
    actual_type, normalized = classify_target(value)
    if expected_type == "asn":
        asn_candidate = value.strip()[2:] if value.strip().lower().startswith("as") else value.strip()
        if is_valid_asn(asn_candidate):
            return True, asn_candidate, None
        return False, value.strip(), f"Expected asn target but received {actual_type!r}: {value}"
    if actual_type != expected_type:
        return False, normalized, f"Expected {expected_type} target but received {actual_type!r}: {value}"
    if expected_type == "domain" and urlparse(value.strip()).scheme:
        return False, normalized, f"Expected domain target but received URL: {value}"
    return True, normalized, None


def normalize_url_target(target: str) -> tuple[str, str]:
    parsed = urlparse(target.strip())
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return normalized, hostname


async def ip_schema_result(target: str, options: InvestigationOptions | None = None) -> InvestigationResultV1:
    opts = options or InvestigationOptions()
    try:
        provider_selection = select_providers(
            target_type="ip",
            mode=opts.mode,
            profile=opts.profile,
            requested_providers=opts.providers,
        )
    except ProviderSelectionError as exc:
        return failed_ip_result_v1(
            target=target,
            error=str(exc),
            mode=opts.mode,
            profile=opts.profile,
            provider_status=ProviderStatus(provider=exc.provider, status="failed", reason=str(exc)),
        )
    except ValueError as exc:
        return failed_ip_result_v1(target=target, error=str(exc), mode=opts.mode, profile=opts.profile)

    try:
        res = await investigate_ip(target)
    except Exception as exc:  # noqa: BLE001
        from tripper_recon.types.models import InvestigationResult
        res = InvestigationResult(ok=False, errors=[f"{type(exc).__name__}: {exc}"], data={})

    return ip_result_to_schema_v1(
        target=target,
        result=res,
        mode=opts.mode,
        profile=opts.profile,
        provider_names=provider_selection.executable,
        extra_provider_statuses=provider_selection.skipped,
    )


async def domain_schema_result(target: str, options: InvestigationOptions | None = None) -> InvestigationResultV1:
    opts = options or InvestigationOptions()
    parsed = urlparse(target)
    norm_domain = parsed.hostname or target.strip().strip("/")
    try:
        provider_selection = select_providers(
            target_type="domain",
            mode=opts.mode,
            profile=opts.profile,
            requested_providers=opts.providers,
        )
    except ProviderSelectionError as exc:
        return failed_domain_result_v1(
            target=target,
            normalized_target=norm_domain,
            error=str(exc),
            mode=opts.mode,
            profile=opts.profile,
            provider_status=ProviderStatus(provider=exc.provider, status="failed", reason=str(exc)),
        )
    except ValueError as exc:
        return failed_domain_result_v1(
            target=target,
            normalized_target=norm_domain,
            error=str(exc),
            mode=opts.mode,
            profile=opts.profile,
        )

    try:
        res = await investigate_domain(norm_domain, mode=opts.mode)
    except Exception as exc:  # noqa: BLE001
        from tripper_recon.types.models import InvestigationResult
        res = InvestigationResult(ok=False, errors=[f"{type(exc).__name__}: {exc}"], data={})

    return domain_result_to_schema_v1(
        target=target,
        normalized_target=norm_domain,
        result=res,
        mode=opts.mode,
        profile=opts.profile,
        provider_names=provider_selection.executable,
        extra_provider_statuses=provider_selection.skipped,
    )


async def url_schema_result(target: str, options: InvestigationOptions | None = None) -> InvestigationResultV1:
    opts = options or InvestigationOptions()
    normalized_url, extracted_domain = normalize_url_target(target)
    try:
        provider_selection = select_providers(
            target_type="url",
            mode=opts.mode,
            profile=opts.profile,
            requested_providers=opts.providers,
        )
    except ProviderSelectionError as exc:
        return failed_url_result_v1(
            target=target,
            normalized_target=normalized_url,
            error=str(exc),
            mode=opts.mode,
            profile=opts.profile,
            provider_status=ProviderStatus(provider=exc.provider, status="failed", reason=str(exc)),
        )
    except ValueError as exc:
        return failed_url_result_v1(
            target=target,
            normalized_target=normalized_url,
            error=str(exc),
            mode=opts.mode,
            profile=opts.profile,
        )

    provider_statuses = list(provider_selection.skipped)
    for provider in provider_selection.executable:
        provider_statuses.append(
            ProviderStatus(
                provider=provider,
                status="missing_credentials",
                reason="No passive URL observation data returned by this schema slice.",
            )
        )

    return url_result_to_schema_v1(
        target=target,
        normalized_target=normalized_url,
        extracted_domain=extracted_domain,
        mode=opts.mode,
        profile=opts.profile,
        provider_statuses=provider_statuses,
    )


async def schema_result_for_target(target: str, options: InvestigationOptions | None = None) -> InvestigationResultV1:
    opts = options or InvestigationOptions()
    target_type, normalized = classify_target(target)
    if target_type == "ip":
        return await ip_schema_result(normalized, opts)
    if target_type == "domain":
        return await domain_schema_result(normalized, opts)
    if target_type == "url":
        return await url_schema_result(normalized, opts)
    return failed_result_v1(
        target_type=target_type,  # type: ignore[arg-type]
        target=target,
        normalized_target=normalized,
        mode=opts.mode,
        profile=opts.profile,
        error=f"Target type {target_type!r} is not implemented for schema v1 output yet.",
    )
