from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi import FastAPI, HTTPException

from tripper_recon.orchestrators import investigate_asn, investigate_domain, investigate_ip
from tripper_recon.utils.env import load_env


# Load .env once on import (safe no-op if missing)
load_env()

app = FastAPI(title="tripper-recon API", version="0.1.0")


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/ip/{ip}")
async def api_ip(ip: str) -> Dict[str, Any]:
    res = await investigate_ip(ip)
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.errors)
    return res.model_dump()


@app.get("/domain/{domain}")
async def api_domain(domain: str) -> Dict[str, Any]:
    res = await investigate_domain(domain)
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.errors)
    return res.model_dump()


@app.get("/asn/{asn}")
async def api_asn(asn: int) -> Dict[str, Any]:
    res = await investigate_asn(asn)
    if not res.ok:
        raise HTTPException(status_code=400, detail=res.errors)
    return res.model_dump()


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

