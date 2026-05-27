## Parent PRD

`issues/prd.md`

## What to build

Add URL investigation as a passive-first path. The URL flow should normalize the URL, query only read-only prior-observation providers when available, extract and relate the domain without local resolution in passive mode, and return `unknown` when no passive observations exist.

## Acceptance criteria

- [ ] `tripper-recon url TARGET --mode passive --json` returns a schema v1 result.
- [ ] URL targets are normalized and represented separately from extracted domain relationships.
- [ ] Passive URL investigation does not submit, fetch, resolve, render, screenshot, follow redirects, or inspect TLS.
- [ ] A URL with no prior passive observations returns `execution_status=completed` and `verdict=unknown`.
- [ ] Tests assert non-contact behavior and unknown verdict behavior for no-observation URLs.

## Blocked by

- Blocked by `issues/002-passive-mode-provider-registry.md`
- Blocked by `issues/005-cli-machine-output-contract.md`
- Blocked by `issues/007-strict-target-typing-and-investigate-router.md`

## User stories addressed

- User story 8
