## Parent PRD

`issues/prd.md`

## What to build

Add the provider capability registry and mode enforcement needed to make passive behavior explicit. This slice should route at least one existing provider set through the registry so skipped, blocked, available, missing-credential, and failed providers appear in `provider_status`.

## Acceptance criteria

- [ ] `Mode` supports at least `passive` and `resolver-passive`.
- [ ] `Capability` supports `provider_observation`, `analyst_resolver`, `brokered_active`, and `direct_active`.
- [ ] Existing providers used by the first schema v1 path are registered with capabilities.
- [ ] Default mode is `passive`.
- [ ] Default disallowed providers are skipped without execution and recorded in `provider_status`.
- [ ] Explicitly requested disallowed providers fail the request with structured errors.
- [ ] Tests cover default skip behavior and explicit disallowed-provider failure.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`

## User stories addressed

- User story 1
- User story 3
- User story 4
