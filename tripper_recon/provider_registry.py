from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from tripper_recon.schema_v1 import ProviderStatus, TargetType


class Mode(str, Enum):
    PASSIVE = "passive"
    RESOLVER_PASSIVE = "resolver-passive"


class Capability(str, Enum):
    PROVIDER_OBSERVATION = "provider_observation"
    ANALYST_RESOLVER = "analyst_resolver"
    BROKERED_ACTIVE = "brokered_active"
    DIRECT_ACTIVE = "direct_active"


@dataclass(frozen=True)
class ProviderEntry:
    name: str
    capability: Capability
    target_types: frozenset[TargetType]


@dataclass(frozen=True)
class ProviderSelection:
    executable: tuple[str, ...]
    skipped: tuple[ProviderStatus, ...]


class ProviderSelectionError(ValueError):
    def __init__(self, *, provider: str, mode: Mode, capability: Capability) -> None:
        self.provider = provider
        self.mode = mode
        self.capability = capability
        super().__init__(
            f"Provider {provider!r} with capability {capability.value!r} is not allowed in mode {mode.value!r}."
        )


PROVIDER_REGISTRY: dict[str, ProviderEntry] = {
    "ipinfo": ProviderEntry("ipinfo", Capability.PROVIDER_OBSERVATION, frozenset({"ip", "asn"})),
    "virustotal": ProviderEntry("virustotal", Capability.PROVIDER_OBSERVATION, frozenset({"ip", "domain", "url"})),
    "shodan": ProviderEntry("shodan", Capability.PROVIDER_OBSERVATION, frozenset({"ip"})),
    "abuseipdb": ProviderEntry("abuseipdb", Capability.PROVIDER_OBSERVATION, frozenset({"ip"})),
    "otx": ProviderEntry("otx", Capability.PROVIDER_OBSERVATION, frozenset({"ip", "domain", "url"})),
    "cloudflare_asn": ProviderEntry("cloudflare_asn", Capability.PROVIDER_OBSERVATION, frozenset({"ip", "asn"})),
    "local_dns": ProviderEntry("local_dns", Capability.ANALYST_RESOLVER, frozenset({"ip", "domain"})),
    "urlscan_submit": ProviderEntry("urlscan_submit", Capability.BROKERED_ACTIVE, frozenset({"url"})),
    "direct_http": ProviderEntry("direct_http", Capability.DIRECT_ACTIVE, frozenset({"url", "domain"})),
}


PROFILE_PROVIDERS: dict[tuple[str, TargetType], tuple[str, ...]] = {
    ("best_effort", "ip"): ("ipinfo", "virustotal", "shodan", "abuseipdb", "otx", "local_dns"),
    ("best_effort", "domain"): ("virustotal", "otx", "local_dns"),
    ("best_effort", "url"): ("virustotal", "otx", "urlscan_submit", "direct_http"),
}


MODE_CAPABILITIES: dict[Mode, frozenset[Capability]] = {
    Mode.PASSIVE: frozenset({Capability.PROVIDER_OBSERVATION}),
    Mode.RESOLVER_PASSIVE: frozenset({Capability.PROVIDER_OBSERVATION, Capability.ANALYST_RESOLVER}),
}


def normalize_mode(value: str | Mode = Mode.PASSIVE) -> Mode:
    if isinstance(value, Mode):
        return value
    return Mode(value)


def select_providers(
    *,
    target_type: TargetType,
    mode: str | Mode = Mode.PASSIVE,
    profile: str = "best_effort",
    requested_providers: list[str] | tuple[str, ...] | None = None,
) -> ProviderSelection:
    selected_mode = normalize_mode(mode)
    provider_names = tuple(requested_providers or PROFILE_PROVIDERS.get((profile, target_type), ()))
    allowed_capabilities = MODE_CAPABILITIES[selected_mode]
    executable: list[str] = []
    skipped: list[ProviderStatus] = []

    for provider_name in provider_names:
        entry = PROVIDER_REGISTRY.get(provider_name)
        if entry is None:
            raise ValueError(f"Unknown provider {provider_name!r}.")
        if target_type not in entry.target_types:
            raise ValueError(f"Provider {provider_name!r} does not support target type {target_type!r}.")
        if entry.capability not in allowed_capabilities:
            if requested_providers is not None:
                raise ProviderSelectionError(provider=provider_name, mode=selected_mode, capability=entry.capability)
            skipped.append(
                ProviderStatus(
                    provider=provider_name,
                    status="skipped",
                    reason=f"Capability {entry.capability.value} is not allowed in mode {selected_mode.value}.",
                )
            )
            continue
        executable.append(provider_name)

    return ProviderSelection(executable=tuple(executable), skipped=tuple(skipped))
