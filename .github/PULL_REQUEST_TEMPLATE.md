<!--
Fill in every section. Delete a section only when it does not apply, and say why.
The two boxes under "Passivity and credential gate" are required. A reviewer must
not approve this pull request while either box is empty.
-->

## Summary

<!-- One or two sentences. What does this pull request do, and why now? -->

## What changed

<!--
List the changes by file or by module. Name the behavior that changed, not only
the lines. Example:

- `utils/redact.py` — new. Strips sensitive query parameters from a URL.
- `orchestrators.py` — `_error_payload` now redacts `url` and `message`.
-->

## Roadmap item

<!--
Reference the item in docs/ROADMAP.md that this pull request delivers, for
example "W0 item 0.1" or "W1 item 1.7". Write "none" for unplanned work, and
say what prompted it.
-->

## Test plan

<!--
Give the exact commands a reviewer can run, and the result you saw.

```
python -m pytest tests/ -q
python -m ruff check .
python -m mypy tripper_recon/
```

For a fix, name the test that fails against the old code. A test that passes
before and after the change proves nothing.
-->

- [ ] New tests cover the changed behavior.
- [ ] The full suite passes locally.
- [ ] The suite makes zero network calls. All HTTP is mocked with `respx`.

## Passivity and credential gate

**Both boxes are required.** These two properties are the contract of the tool.
A reviewer who cannot confirm both must request changes.

- [ ] This PR adds no request to a host the target controls, and no endpoint from the forbidden list in docs/OPSEC.md section 7.
- [ ] No credential can reach output. No API key, token, or `Authorization` header value can appear in the console render, the JSON export, a log line, or an error payload.

<!--
How to confirm the first box:
- Every new outbound call goes to a third-party provider in the table in
  docs/OPSEC.md section 2.
- No new call reaches the target, and no new call asks a provider to fetch the
  target. A submission endpoint, a live scan, and a redirect expansion are all
  active, even when the method is HEAD.
- If this PR adds a provider, add a row to the table in docs/OPSEC.md section 2
  in the same commit.

How to confirm the second box:
- Shodan and IPInfo carry the key in the query string. Any code path that copies
  a request URL or an exception string into output must pass it through
  `utils/redact.py` first.
- Run the tool against a bad key and read the error output. The key must not
  appear.
-->

## Documentation

- [ ] `docs/OPSEC.md` matches the code after this change, or the change does not touch outbound behavior.
- [ ] `README.md` claims nothing this pull request does not deliver.

## Risk and rollback

<!--
Name the way this change can fail in front of an analyst, and the way to undo
it. Write "low risk, revert the commit" when that is true.
-->
