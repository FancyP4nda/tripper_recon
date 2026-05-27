## Parent PRD

`issues/prd.md`

## What to build

Create the first end-to-end schema v1 path for a single IP investigation. The result model should expose the machine-readable contract described in PRD sections 3, 4, and 6 while preserving enough existing provider orchestration to return a demoable `tripper-recon ip ... --json` response and matching API response.

## Acceptance criteria

- [ ] Schema v1 models exist for target metadata, execution status, verdict, score, confidence, findings, relationships, provider status, evidence, cache metadata, errors, and warnings.
- [ ] A single IP investigation can return a schema v1 object through both CLI JSON output and the API.
- [ ] Machine-readable schema v1 output does not include top-level `ok`.
- [ ] Legacy `InvestigationResult` behavior is either adapted behind the schema v1 boundary or isolated from new machine output.
- [ ] Tests validate the required top-level schema keys and the absence of top-level `ok`.

## Blocked by

None - can start immediately

## User stories addressed

- User story 5
