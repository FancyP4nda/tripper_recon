from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, HTTPException

from tripper_recon.schema_v1 import failed_result_v1
from tripper_recon.service import InvestigationOptions, domain_schema_result, ip_schema_result, normalize_provider_param, schema_result_for_target
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
    include_raw: bool = False,
    require_profile_complete: bool = False,
    cache: bool = True,
) -> Dict[str, Any]:
    if profile not in {"best_effort", "ciso_daily"}:
        raise HTTPException(status_code=400, detail=["Unsupported profile for schema v1 IP path"])
    result = await ip_schema_result(
        ip,
        InvestigationOptions(
            mode=mode,
            profile=profile,
            providers=normalize_provider_param(providers),
            include_raw=include_raw,
            require_profile_complete=require_profile_complete,
            cache=cache,
        ),
    )
    return result.model_dump()


@app.get("/domain/{domain}")
async def api_domain(
    domain: str,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
    include_raw: bool = False,
    require_profile_complete: bool = False,
    cache: bool = True,
) -> Dict[str, Any]:
    if profile not in {"best_effort", "ciso_daily"}:
        raise HTTPException(status_code=400, detail=["Unsupported profile for schema v1 domain path"])
    result = await domain_schema_result(
        domain,
        InvestigationOptions(
            mode=mode,
            profile=profile,
            providers=normalize_provider_param(providers),
            include_raw=include_raw,
            require_profile_complete=require_profile_complete,
            cache=cache,
        ),
    )
    return result.model_dump()


@app.get("/url")
async def api_url(
    target: str,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
    include_raw: bool = False,
    require_profile_complete: bool = False,
    cache: bool = True,
) -> Dict[str, Any]:
    result = await schema_result_for_target(
        target,
        InvestigationOptions(
            mode=mode,
            profile=profile,
            providers=normalize_provider_param(providers),
            include_raw=include_raw,
            require_profile_complete=require_profile_complete,
            cache=cache,
        ),
    )
    return result.model_dump()


@app.get("/investigate")
async def api_investigate(
    target: str,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
    include_raw: bool = False,
    require_profile_complete: bool = False,
    cache: bool = True,
) -> Dict[str, Any]:
    result = await schema_result_for_target(
        target,
        InvestigationOptions(
            mode=mode,
            profile=profile,
            providers=normalize_provider_param(providers),
            include_raw=include_raw,
            require_profile_complete=require_profile_complete,
            cache=cache,
        ),
    )
    return result.model_dump()


@app.get("/asn/{asn}")
async def api_asn(
    asn: int,
    mode: str = "passive",
    profile: str = "best_effort",
    providers: str | None = None,
    include_raw: bool = False,
    require_profile_complete: bool = False,
    cache: bool = True,
) -> Dict[str, Any]:
    _ = (providers, include_raw, require_profile_complete, cache)
    return failed_result_v1(
        target_type="asn",
        target=str(asn),
        normalized_target=str(asn),
        mode=mode,
        profile=profile,
        error="Target type 'asn' is not implemented for schema v1 API output yet.",
    ).model_dump()


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

