## Parent PRD

`issues/prd.md`

## What to build

Implement explicit raw evidence inclusion with sanitization. Raw-ish provider payloads should be omitted by default, bounded when requested, redacted before output or caching, and annotated when truncation occurs.

## Acceptance criteria

- [ ] `include_raw=false` remains the default.
- [ ] `include_raw=true` emits sanitized raw-ish provider payloads under evidence records.
- [ ] Request headers are never emitted.
- [ ] Sensitive fields and query parameters such as `token`, `key`, `api_key`, and `apikey` are redacted from output, errors, logs, and cache metadata.
- [ ] Raw payloads are size-capped per provider and include truncation metadata when capped.
- [ ] Tests cover header omission, sensitive value redaction, and truncation metadata.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`
- Blocked by `issues/002-passive-mode-provider-registry.md`

## User stories addressed

- User story 9
