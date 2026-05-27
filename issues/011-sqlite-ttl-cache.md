## Parent PRD

`issues/prd.md`

## What to build

Add a SQLite TTL cache for provider observations. Cache behavior should be transparent in schema v1 output and safe for passive workflows, including schema-version separation and sanitized raw payload storage only.

## Acceptance criteria

- [ ] Cache keys include normalized target, target type, mode, provider, and schema version.
- [ ] Provider-specific TTLs and evidence-class default TTLs are supported.
- [ ] Results disclose cache hit/miss status and retrieval timestamps.
- [ ] Provider-native timestamps such as `observed_at`, `first_seen`, or `last_seen` are preserved when available.
- [ ] Schema version changes do not reuse stale cache entries from another schema version.
- [ ] Tests cover hit, miss, TTL expiry, provider-specific TTL, schema-version separation, and sanitized raw storage.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`
- Blocked by `issues/009-sanitized-raw-evidence.md`

## User stories addressed

- User story 11
