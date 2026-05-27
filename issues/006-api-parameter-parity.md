## Parent PRD

`issues/prd.md`

## What to build

Update the FastAPI surface so API callers can use the same schema v1 service-layer options as CLI callers. The API should return the same normalized result shape for IP, domain, URL, ASN, and investigate paths as those paths become available.

## Acceptance criteria

- [ ] API routes accept `mode`, `profile`, `include_raw`, requested providers, profile completeness, and cache controls where applicable.
- [ ] API responses use schema v1 result objects instead of the legacy top-level `ok` machine contract.
- [ ] `/ip/{target}` and `/domain/{target}` exercise the shared service layer rather than duplicating CLI logic.
- [ ] API validation errors are structured and do not leak secrets or request headers.
- [ ] Tests validate parameter parsing and schema parity for at least IP and domain routes.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`
- Blocked by `issues/002-passive-mode-provider-registry.md`

## User stories addressed

- User story 5
- User story 12
