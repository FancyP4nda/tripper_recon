from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi import FastAPI, HTTPException

from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.provider_registry import ProviderSelectionError, select_providers
from tripper_recon.schema_v1 import (
    ProviderStatus,
    domain_result_to_schema_v1,
    failed_domain_result_v1,
    failed_ip_result_v1,
    ip_result_to_schema_v1,
)
from tripper_recon.utils.env import load_env


# Load .env once on import (safe no-op if missing)
load_env()

app = FastAPI(title="tripper-recon API", version="0.1.0")


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/ip/{ip}")
async def api_ip(
    ip: str,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
) -> Dict[str, Any]:
    if profile != "best_effort":
        raise HTTPException(status_code=400, detail=["Unsupported profile for schema v1 IP path"])
    requested_providers = [value.strip() for value in providers.split(",") if value.strip()] if providers else None
    try:
        provider_selection = select_providers(
            target_type="ip",
            mode=mode,
            profile=profile,
            requested_providers=requested_providers,
        )
    except ProviderSelectionError as exc:
        status = ProviderStatus(provider=exc.provider, status="failed", reason=str(exc))
        return failed_ip_result_v1(
            target=ip,
            error=str(exc),
            mode=mode,
            profile=profile,
            provider_status=status,
        ).model_dump()
    except ValueError as exc:
        return failed_ip_result_v1(target=ip, error=str(exc), mode=mode, profile=profile).model_dump()
    res = await investigate_ip(ip)
    if not res.ok:
        return ip_result_to_schema_v1(
            target=ip,
            result=res,
            mode=mode,
            profile=profile,
            provider_names=provider_selection.executable,
            extra_provider_statuses=provider_selection.skipped,
        ).model_dump()
    return ip_result_to_schema_v1(
        target=ip,
        result=res,
        mode=mode,
        profile=profile,
        provider_names=provider_selection.executable,
        extra_provider_statuses=provider_selection.skipped,
    ).model_dump()


@app.get("/domain/{domain}")
async def api_domain(
    domain: str,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
) -> Dict[str, Any]:
    if profile != "best_effort":
        raise HTTPException(status_code=400, detail=["Unsupported profile for schema v1 domain path"])
    requested_providers = [value.strip() for value in providers.split(",") if value.strip()] if providers else None
    try:
        provider_selection = select_providers(
            target_type="domain",
            mode=mode,
            profile=profile,
            requested_providers=requested_providers,
        )
    except ProviderSelectionError as exc:
        status = ProviderStatus(provider=exc.provider, status="failed", reason=str(exc))
        return failed_domain_result_v1(
            target=domain,
            normalized_target=domain,
            error=str(exc),
            mode=mode,
            profile=profile,
            provider_status=status,
        ).model_dump()
    except ValueError as exc:
        return failed_domain_result_v1(
            target=domain,
            normalized_target=domain,
            error=str(exc),
            mode=mode,
            profile=profile,
        ).model_dump()

    res = await investigate_domain(domain, mode=mode)
    if not res.ok:
        return domain_result_to_schema_v1(
            target=domain,
            normalized_target=domain,
            result=res,
            mode=mode,
            profile=profile,
            provider_names=provider_selection.executable,
            extra_provider_statuses=provider_selection.skipped,
        ).model_dump()
    return domain_result_to_schema_v1(
        target=domain,
        normalized_target=domain,
        result=res,
        mode=mode,
        profile=profile,
        provider_names=provider_selection.executable,
        extra_provider_statuses=provider_selection.skipped,
    ).model_dump()


@app.get("/asn/{asn}")
async def api_asn(asn: int) -> Dict[str, Any]:
    res = await investigate_asn(asn)
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.errors)
    return res.model_dump()


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

