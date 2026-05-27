## Parent PRD

`issues/prd.md`

## What to build

Define and implement the report-grade `ciso_daily` profile completeness policy. This is marked HITL because the PRD requires minimum evidence sets by target type but does not define the exact minimum coverage rules.

## Acceptance criteria

- [ ] Human-approved minimum evidence sets are documented for IP, domain, URL, and ASN targets.
- [ ] `profile=ciso_daily` applies the approved target-type-specific minimum coverage policy.
- [ ] `require_profile_complete=true` fails with a structured profile completeness error when minimum coverage is unavailable.
- [ ] Missing credentials or optional provider outages still produce partial coverage under `best_effort`.
- [ ] Tests cover complete and incomplete `ciso_daily` coverage for at least two target types.

## Blocked by

- Blocked by `issues/002-passive-mode-provider-registry.md`
- Blocked by `issues/005-cli-machine-output-contract.md`
- Blocked by `issues/006-api-parameter-parity.md`

## User stories addressed

- User story 12
