from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tripper_recon.schema_v1 import SCHEMA_VERSION, CacheInfo, TargetType, _sanitize_for_output


DEFAULT_TTLS_SECONDS: dict[str, int] = {
    "reputation": 6 * 60 * 60,
    "context": 24 * 60 * 60,
    "relationship": 12 * 60 * 60,
}

PROVIDER_TTLS_SECONDS: dict[str, int] = {
    "virustotal": 6 * 60 * 60,
    "abuseipdb": 6 * 60 * 60,
    "otx": 6 * 60 * 60,
    "shodan": 12 * 60 * 60,
    "ipinfo": 24 * 60 * 60,
    "cloudflare_asn": 24 * 60 * 60,
}


@dataclass(frozen=True)
class CachedObservation:
    provider: str
    evidence_class: str
    payload: dict[str, Any]
    retrieved_at: str
    observed_at: str | None


def cache_path() -> Path:
    configured = os.getenv("TRIPPER_RECON_CACHE_DB")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent.parent / "outputs" / "provider-cache.sqlite3"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def evidence_class_for_provider(provider: str, target_type: TargetType) -> str:
    if provider in {"ipinfo", "shodan", "cloudflare_asn", "asn_meta"}:
        return "context"
    if provider in {"local_dns", "url_parser"} or target_type in {"domain", "url"} and provider == "virustotal":
        return "relationship" if provider == "local_dns" else "reputation"
    return "reputation"


def ttl_seconds(provider: str, evidence_class: str) -> int:
    return PROVIDER_TTLS_SECONDS.get(provider, DEFAULT_TTLS_SECONDS.get(evidence_class, DEFAULT_TTLS_SECONDS["context"]))


def extract_provider_timestamp(payload: dict[str, Any]) -> str | None:
    for key in ("observed_at", "first_seen", "last_seen", "last_analysis_date", "last_modification_date"):
        value = payload.get(key)
        if value is not None:
            return str(value)
    return None


class ProviderCache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or cache_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS provider_observations (
                    normalized_target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    evidence_class TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    observed_at TEXT,
                    PRIMARY KEY (normalized_target, target_type, mode, provider, schema_version)
                )
                """
            )

    def get(
        self,
        *,
        normalized_target: str,
        target_type: TargetType,
        mode: str,
        provider: str,
        schema_version: str = SCHEMA_VERSION,
        now: datetime | None = None,
    ) -> CachedObservation | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT evidence_class, payload_json, retrieved_at, observed_at
                FROM provider_observations
                WHERE normalized_target = ?
                  AND target_type = ?
                  AND mode = ?
                  AND provider = ?
                  AND schema_version = ?
                """,
                (normalized_target, target_type, mode, provider, schema_version),
            ).fetchone()
        if row is None:
            return None
        evidence_class, payload_json, retrieved_at, observed_at = row
        age = (now or utc_now()) - parse_iso(str(retrieved_at))
        if age > timedelta(seconds=ttl_seconds(provider, str(evidence_class))):
            return None
        payload = json.loads(str(payload_json))
        return CachedObservation(
            provider=provider,
            evidence_class=str(evidence_class),
            payload=payload,
            retrieved_at=str(retrieved_at),
            observed_at=str(observed_at) if observed_at else None,
        )

    def set(
        self,
        *,
        normalized_target: str,
        target_type: TargetType,
        mode: str,
        provider: str,
        payload: dict[str, Any],
        evidence_class: str | None = None,
        schema_version: str = SCHEMA_VERSION,
        retrieved_at: datetime | None = None,
    ) -> CacheInfo:
        clean_payload = _sanitize_for_output(payload)
        if not isinstance(clean_payload, dict):
            clean_payload = {"value": clean_payload}
        evidence_class = evidence_class or evidence_class_for_provider(provider, target_type)
        retrieved = isoformat(retrieved_at or utc_now())
        observed_at = extract_provider_timestamp(clean_payload)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_observations (
                    normalized_target, target_type, mode, provider, schema_version,
                    evidence_class, payload_json, retrieved_at, observed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(normalized_target, target_type, mode, provider, schema_version)
                DO UPDATE SET
                    evidence_class = excluded.evidence_class,
                    payload_json = excluded.payload_json,
                    retrieved_at = excluded.retrieved_at,
                    observed_at = excluded.observed_at
                """,
                (
                    normalized_target,
                    target_type,
                    mode,
                    provider,
                    schema_version,
                    evidence_class,
                    json.dumps(clean_payload, sort_keys=True, separators=(",", ":"), default=str),
                    retrieved,
                    observed_at,
                ),
            )
        return CacheInfo(hit=False, provider=provider, retrieved_at=retrieved, observed_at=observed_at)

    def get_many(
        self,
        *,
        normalized_target: str,
        target_type: TargetType,
        mode: str,
        providers: tuple[str, ...],
        schema_version: str = SCHEMA_VERSION,
        now: datetime | None = None,
    ) -> tuple[dict[str, CachedObservation], list[CacheInfo]]:
        observations: dict[str, CachedObservation] = {}
        cache_info: list[CacheInfo] = []
        for provider in providers:
            cached = self.get(
                normalized_target=normalized_target,
                target_type=target_type,
                mode=mode,
                provider=provider,
                schema_version=schema_version,
                now=now,
            )
            if cached is None:
                cache_info.append(CacheInfo(hit=False, provider=provider, retrieved_at=isoformat(now or utc_now())))
                continue
            observations[provider] = cached
            cache_info.append(
                CacheInfo(
                    hit=True,
                    provider=provider,
                    retrieved_at=cached.retrieved_at,
                    observed_at=cached.observed_at,
                )
            )
        return observations, cache_info

