## Parent PRD

`issues/prd.md`

## What to build

Align CLI machine output with schema v1 for single-target and batch workflows. The CLI should accept the PRD-defined options and keep stdout reserved for valid JSON or JSONL while diagnostics and summaries go to stderr or explicit files.

## Acceptance criteria

- [ ] CLI supports `--mode`, `--profile`, `--include-raw`, requested providers, profile completeness, and cache controls for schema v1 paths.
- [ ] Single-target `--json` output writes exactly one valid schema v1 JSON object to stdout.
- [ ] Batch `investigate --json` output writes one complete schema v1 JSON object per line.
- [ ] Logs, diagnostics, and batch summaries do not appear in stdout in machine modes.
- [ ] Human console output remains available and is rendered from normalized result data.
- [ ] Tests validate stdout/stderr separation for single-target JSON and batch JSONL.

## Blocked by

- Blocked by `issues/001-schema-v1-result-contract.md`
- Blocked by `issues/002-passive-mode-provider-registry.md`

## User stories addressed

- User story 5
- User story 6
- User story 12
