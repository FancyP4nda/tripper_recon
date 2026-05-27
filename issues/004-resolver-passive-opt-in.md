## Parent PRD

`issues/prd.md`

## What to build

Add the explicit `resolver-passive` mode for analyst-controlled DNS/PTR enrichment. This mode should permit local resolver helpers only through the registry while continuing to block direct active and brokered active behavior.

## Acceptance criteria

- [ ] CLI and service calls can select `mode=resolver-passive`.
- [ ] Domain investigation may call DNS/PTR helpers only when `resolver-passive` is selected.
- [ ] HTTP, TLS, redirects, screenshots, crawling, sandbox submissions, and port probing remain blocked in `resolver-passive`.
- [ ] Resolver-derived relationships are distinguishable from provider-observation relationships.
- [ ] Tests prove passive mode blocks DNS/PTR and resolver-passive permits DNS/PTR only by explicit selection.

## Blocked by

- Blocked by `issues/002-passive-mode-provider-registry.md`
- Blocked by `issues/003-passive-domain-non-contact-path.md`

## User stories addressed

- User story 2
