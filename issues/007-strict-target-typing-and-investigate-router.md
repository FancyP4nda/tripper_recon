## Parent PRD

`issues/prd.md`

## What to build

Make typed commands strict and add the mixed-indicator `investigate` path as the batch router. Typed commands should reject wrong target types rather than coercing them, while `investigate` should classify supported indicators and emit schema v1 results in dependency-safe order.

## Acceptance criteria

- [ ] `ip`, `domain`, `url`, and `asn` typed commands reject inputs that do not match their declared target type.
- [ ] `domain https://example.com/path --json` fails validation instead of extracting `example.com`.
- [ ] `investigate` accepts a single target or file containing mixed IP, domain, URL, and ASN indicators.
- [ ] Batch JSONL emits one schema v1 result per input line without summary contamination.
- [ ] Tests cover typed rejection and mixed-indicator routing.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`
- Blocked by `issues/005-cli-machine-output-contract.md`

## User stories addressed

- User story 6
- User story 7
