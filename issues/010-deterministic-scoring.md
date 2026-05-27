## Parent PRD

`issues/prd.md`

## What to build

Add deterministic scoring and verdict assignment from normalized evidence. Scoring should classify evidence as reputation, context, or relationship; compute score and confidence from fixed rules; and attach reasons to evidence IDs.

## Acceptance criteria

- [ ] Evidence records can be classified as reputation, context, or relationship.
- [ ] Fixed provider inputs produce deterministic score, verdict, confidence, and reason output.
- [ ] Context and relationship evidence cannot directly produce a malicious verdict without reputation support.
- [ ] Scoring reasons reference the evidence IDs used in the calculation.
- [ ] Tests cover deterministic replay and the context-only non-malicious verdict rule.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`

## User stories addressed

- User story 10
