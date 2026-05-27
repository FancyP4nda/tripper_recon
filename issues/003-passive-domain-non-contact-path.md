## Parent PRD

`issues/prd.md`

## What to build

Make domain investigation passive by default. A passive domain run should use only already-existing provider observations, preserve passive relationships discovered from those providers, and never call local DNS/PTR helpers or target-origin contact paths.

## Acceptance criteria

- [ ] `tripper-recon domain example.com --mode passive --json` returns a schema v1 result.
- [ ] Passive domain investigation does not call `tripper_recon.utils.dns.resolve_domain` or `reverse_ptr`.
- [ ] Passively discovered IP relationships from provider observations can be represented without local DNS.
- [ ] The result includes mode, provider statuses, evidence, and relationships for the domain path.
- [ ] Tests mock provider observations and assert no local DNS/PTR calls occur in passive mode.

## Blocked by

- Blocked by `issues/002-passive-mode-provider-registry.md`

## User stories addressed

- User story 1
