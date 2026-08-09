"""Tests for the calibration recording harness (``tools/calibrate.py``, roadmap W5.9).

Two properties dominate this file and both are safety properties rather than behaviour ones.

**Nothing here may reach a provider.** The harness exists to spend the operator's quota
deliberately; a test that spent it accidentally would be the exact failure the harness is built
to prevent. Every test drives a fake recorder, and the one class that can reach the network
(:class:`LiveRecorder`) is only ever constructed to watch it refuse.

**The guard must be untestable-around.** ``test_environment_reasons`` takes injectable
``modules`` / ``argv`` / ``env`` precisely so the guard can be exercised from inside a test run,
which is the one environment where the live answer is always "refuse". The tests below check both
directions: the injected clean environment reports no reason, and the *real* one -- this pytest
process -- always does.

The module is loaded by path rather than imported: ``tools/`` is a directory of operator scripts,
not a package, and making it importable would put it on ``sys.path`` for every session.
"""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional, Sequence

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CALIBRATE_PATH = REPO_ROOT / "tools" / "calibrate.py"


def _load_calibrate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("tripper_recon_tools_calibrate", CALIBRATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered so dataclasses and enums defined inside it pickle and repr sanely, and so a
    # second load in the same session returns the same object rather than two divergent copies.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


calibrate = _load_calibrate()

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC)

#: An environment with no test-runner and no CI marker in it. Passed wherever the guard is being
#: exercised for its negative case.
CLEAN_ENV: Dict[str, str] = {"HOME": "/home/operator"}
CLEAN_MODULES: List[str] = ["json", "pathlib"]
CLEAN_ARGV: List[str] = ["tools/calibrate.py", "plan"]


# --------------------------------------------------------------------------------------
# The guard: accidental execution in a test environment must be impossible
# --------------------------------------------------------------------------------------


def test_guard_fires_in_this_pytest_process() -> None:
    """The real, un-injected guard refuses here. This is the test that matters most.

    If this ever passes by *not* raising, the harness has become runnable from the suite and
    every other safety property in this file is decoration.
    """
    with pytest.raises(calibrate.GuardError) as excinfo:
        calibrate.assert_not_test_environment()
    assert "refuses to run here" in str(excinfo.value)


def test_guard_reports_every_reason_it_found() -> None:
    reasons = calibrate.test_environment_reasons()
    assert reasons, "the guard found no reason to refuse inside a pytest process"
    joined = "\n".join(reasons)
    assert "pytest" in joined


def test_guard_is_silent_in_a_clean_environment() -> None:
    """The guard is not a blanket refusal: given a clean process it permits the run."""
    assert calibrate.test_environment_reasons(modules=CLEAN_MODULES, argv=CLEAN_ARGV, env=CLEAN_ENV) == []
    calibrate.assert_not_test_environment(modules=CLEAN_MODULES, argv=CLEAN_ARGV, env=CLEAN_ENV)


@pytest.mark.parametrize("variable", ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TF_BUILD"])
def test_guard_refuses_under_each_ci_marker(variable: str) -> None:
    env = {**CLEAN_ENV, variable: "true"}
    with pytest.raises(calibrate.GuardError) as excinfo:
        calibrate.assert_not_test_environment(modules=CLEAN_MODULES, argv=CLEAN_ARGV, env=env)
    assert variable in str(excinfo.value)


def test_guard_ignores_an_empty_ci_variable() -> None:
    """``CI=`` is how a shell unsets-by-blanking. An empty value is not a CI system."""
    env = {**CLEAN_ENV, "CI": "   "}
    assert calibrate.test_environment_reasons(modules=CLEAN_MODULES, argv=CLEAN_ARGV, env=env) == []


def test_guard_refuses_when_pytest_current_test_is_set() -> None:
    env = {**CLEAN_ENV, calibrate.PYTEST_ENV_VAR: "tests/test_x.py::test_y (call)"}
    with pytest.raises(calibrate.GuardError):
        calibrate.assert_not_test_environment(modules=CLEAN_MODULES, argv=CLEAN_ARGV, env=env)


def test_guard_refuses_when_unittest_is_loaded() -> None:
    """Not only pytest. The rule is "no test runner", so the check names more than one."""
    with pytest.raises(calibrate.GuardError):
        calibrate.assert_not_test_environment(modules=["unittest"], argv=CLEAN_ARGV, env=CLEAN_ENV)


def test_live_recorder_cannot_be_constructed_in_a_test_run() -> None:
    """The one object that reaches the network refuses to exist here.

    This is what makes the guard structural rather than advisory: a test cannot obtain a live
    recorder to drive, however it is written.
    """
    with pytest.raises(calibrate.GuardError):
        calibrate.LiveRecorder()


def test_main_refuses_every_subcommand_in_a_test_run(capsys: pytest.CaptureFixture[str]) -> None:
    """Including the offline ones. The guard is unconditional and precedes argument parsing."""
    for argv in (["plan", "--labels", "x.csv"], ["record", "--labels", "x.csv"], ["evaluate"]):
        assert calibrate.main(argv) == calibrate.EXIT_GUARD
    captured = capsys.readouterr().out
    assert captured.count("REFUSED") == 3


def test_main_refuses_before_parsing_a_bad_argument_list() -> None:
    """argparse never runs, so a usage error cannot mask the refusal (or vice versa)."""
    assert calibrate.main(["not-a-subcommand"]) == calibrate.EXIT_GUARD


# --------------------------------------------------------------------------------------
# The labelled indicator set
# --------------------------------------------------------------------------------------

GOOD_CSV = """indicator,label,label_source,first_seen,note
198.51.100.7,malicious,urlhaus,2026-05-01,C2 host
93.184.216.34,benign,tranco,2026-01-02,
evil-example.test,malicious,urlhaus,2026-06-15,
hxxp://evil-example[.]test/payload.bin,bad,urlhaus,2026-06-15,defanged on purpose
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_load_label_set_parses_and_refangs(tmp_path: Path) -> None:
    label_set = calibrate.load_label_set(_write(tmp_path, "labels.csv", GOOD_CSV))
    assert len(label_set.rows) == 4
    assert label_set.problems == ()

    by_scope = {row.scope for row in label_set.rows}
    assert by_scope == {calibrate.Scope.IP, calibrate.Scope.DOMAIN, calibrate.Scope.URL}

    url_row = next(row for row in label_set.rows if row.scope is calibrate.Scope.URL)
    assert url_row.raw.startswith("hxxp://")
    assert url_row.value.startswith("http://evil-example.test/")
    assert url_row.label is calibrate.Label.MALICIOUS


def test_label_set_records_first_seen_as_utc(tmp_path: Path) -> None:
    label_set = calibrate.load_label_set(_write(tmp_path, "labels.csv", GOOD_CSV))
    row = next(row for row in label_set.rows if row.value == "198.51.100.7")
    assert row.first_seen == dt.datetime(2026, 5, 1, tzinfo=UTC)


def test_label_set_rejects_a_naive_datetime(tmp_path: Path) -> None:
    """A temporal split shifted by the operator's offset is the one error the split exists to avoid."""
    csv_text = "indicator,label,label_source,first_seen\n1.2.3.4,malicious,urlhaus,2026-05-01T12:30:00\n"
    label_set_error = calibrate.LabelSetError
    with pytest.raises(label_set_error):
        calibrate.load_label_set(_write(tmp_path, "naive.csv", csv_text))


def test_label_set_reports_unusable_rows_rather_than_dropping_them(tmp_path: Path) -> None:
    csv_text = (
        "indicator,label,label_source\n"
        "1.2.3.4,malicious,urlhaus\n"
        "AS13335,malicious,urlhaus\n"
        "5.6.7.8,definitely-bad,urlhaus\n"
        "9.9.9.9,malicious,some-feed-nobody-declared\n"
        ",malicious,urlhaus\n"
    )
    label_set = calibrate.load_label_set(_write(tmp_path, "mixed.csv", csv_text))
    assert [row.value for row in label_set.rows] == ["1.2.3.4"]
    reasons = " | ".join(problem.reason for problem in label_set.problems)
    assert "asn" in reasons
    assert "definitely-bad" in reasons
    assert "some-feed-nobody-declared" in reasons
    assert "no indicator" in reasons


def test_label_set_collapses_duplicates_and_says_so(tmp_path: Path) -> None:
    csv_text = "indicator,label,label_source\n1.2.3.4,malicious,urlhaus\n1.2.3.4,malicious,urlhaus\n"
    label_set = calibrate.load_label_set(_write(tmp_path, "dupes.csv", csv_text))
    assert len(label_set.rows) == 1
    assert label_set.duplicates_removed == 1


def test_label_set_requires_a_label_source(tmp_path: Path) -> None:
    csv_text = "indicator,label\n1.2.3.4,malicious\n"
    with pytest.raises(calibrate.LabelSetError) as excinfo:
        calibrate.load_label_set(_write(tmp_path, "nosource.csv", csv_text))
    assert "label_source" in str(excinfo.value)


def test_fixture_id_never_contains_the_indicator(tmp_path: Path) -> None:
    """Attacker-authored text never becomes a path component."""
    csv_text = "indicator,label,label_source\nhttp://evil.test/../../etc/passwd,malicious,urlhaus\n"
    label_set = calibrate.load_label_set(_write(tmp_path, "traversal.csv", csv_text))
    fixture_id = label_set.rows[0].fixture_id
    assert fixture_id.startswith("url-")
    assert "/" not in fixture_id and ".." not in fixture_id


# --------------------------------------------------------------------------------------
# The disclosure plan
# --------------------------------------------------------------------------------------


def _rows(tmp_path: Path, text: str = GOOD_CSV) -> Sequence[Any]:
    return calibrate.load_label_set(_write(tmp_path, "labels.csv", text)).rows


def test_plan_counts_indicators_and_a_minimum_number_of_calls(tmp_path: Path) -> None:
    plan = calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path / "fixtures")
    assert plan.total_indicators == 4
    assert plan.counts[calibrate.Scope.IP] == 2
    assert plan.counts[calibrate.Scope.DOMAIN] == 1
    assert plan.counts[calibrate.Scope.URL] == 1
    assert plan.minimum_calls > 0
    assert plan.unbounded is True


def test_plan_states_the_call_count_as_a_floor_not_an_estimate(tmp_path: Path) -> None:
    rendered = calibrate.render_plan(calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path))
    assert "MINIMUM provider calls" in rendered
    assert "floor, not an estimate" in rendered


def test_plan_names_every_provider_that_will_be_contacted(tmp_path: Path) -> None:
    rendered = calibrate.render_plan(calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path))
    for provider in calibrate.IP_PROVIDERS:
        assert provider in rendered
    for provider in calibrate.DOMAIN_PROVIDERS:
        assert provider in rendered


def test_plan_says_which_providers_log_against_the_operators_account(tmp_path: Path) -> None:
    env = {"VT_API_KEY": "a-real-looking-key", "OTX_API_KEY": ""}
    rendered = calibrate.render_plan(calibrate.build_plan(_rows(tmp_path), env=env, fixture_dir=tmp_path))
    assert "logged against YOUR account" in rendered
    assert "OTX_API_KEY is not set" in rendered
    assert "keyless" in rendered


def test_plan_never_prints_a_credential_value(tmp_path: Path) -> None:
    secret = "vt-key-must-never-appear-in-output"
    rendered = calibrate.render_plan(
        calibrate.build_plan(_rows(tmp_path), env={"VT_API_KEY": secret}, fixture_dir=tmp_path)
    )
    assert secret not in rendered


def test_plan_discloses_the_resolver_step_for_domains(tmp_path: Path) -> None:
    rendered = calibrate.render_plan(calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path))
    assert "SYSTEM" in rendered and "RESOLVER" in rendered
    assert "docs/OPSEC.md section 3" in rendered


def test_plan_for_url_depth_url_is_fully_passive(tmp_path: Path) -> None:
    csv_text = "indicator,label,label_source\nhttp://evil.test/x,malicious,urlhaus\n"
    plan = calibrate.build_plan(_rows(tmp_path, csv_text), env={}, fixture_dir=tmp_path, url_depth="url")
    assert plan.resolves_dns is False
    assert "ACTIVE COLLECTION" not in calibrate.render_plan(plan)


def test_plan_states_that_recording_is_not_validation(tmp_path: Path) -> None:
    rendered = calibrate.render_plan(calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path))
    assert "THIS DOES NOT VALIDATE ANYTHING" in rendered
    assert "not yet validated" in rendered
    assert "never edits" in rendered and "scoring.yaml" in rendered


def test_plan_lists_rejected_rows(tmp_path: Path) -> None:
    csv_text = "indicator,label,label_source\n1.2.3.4,malicious,urlhaus\nAS13335,malicious,urlhaus\n"
    label_set = calibrate.load_label_set(_write(tmp_path, "labels.csv", csv_text))
    plan = calibrate.build_plan(label_set.rows, env={}, fixture_dir=tmp_path, label_problems=label_set.problems)
    assert "ROWS REJECTED FROM THE LABEL SET" in calibrate.render_plan(plan)


# --------------------------------------------------------------------------------------
# Confirmation
# --------------------------------------------------------------------------------------


class _Recorded:
    def __init__(self) -> None:
        self.text = ""

    def write(self, chunk: str) -> int:
        self.text += chunk
        return len(chunk)

    def flush(self) -> None:
        return None


def _plan(tmp_path: Path) -> Any:
    return calibrate.build_plan(_rows(tmp_path), env={}, fixture_dir=tmp_path)


def test_confirmation_requires_the_exact_phrase(tmp_path: Path) -> None:
    stream = _Recorded()
    with pytest.raises(calibrate.ConfirmationError):
        calibrate.confirm(_plan(tmp_path), stream=stream, reader=lambda: "y", interactive=True)
    assert "nothing was contacted" not in stream.text  # the reason travels on the exception


def test_confirmation_accepts_the_phrase(tmp_path: Path) -> None:
    stream = _Recorded()
    calibrate.confirm(
        _plan(tmp_path), stream=stream, reader=lambda: f"  {calibrate.CONFIRMATION_PHRASE}  ", interactive=True
    )
    assert calibrate.CONFIRMATION_PHRASE in stream.text


def test_confirmation_prints_the_plan_before_asking(tmp_path: Path) -> None:
    stream = _Recorded()
    with pytest.raises(calibrate.ConfirmationError):
        calibrate.confirm(_plan(tmp_path), stream=stream, reader=lambda: "no", interactive=True)
    assert stream.text.index("WHAT YOU ARE ABOUT TO DO") < stream.text.index("Type exactly")


def test_confirmation_refuses_a_non_interactive_stdin(tmp_path: Path) -> None:
    """A process that cannot be asked has not agreed. This is the second CI/scheduler barrier."""
    with pytest.raises(calibrate.ConfirmationError) as excinfo:
        calibrate.confirm(
            _plan(tmp_path),
            stream=_Recorded(),
            reader=lambda: calibrate.CONFIRMATION_PHRASE,
            interactive=False,
        )
    assert "not an interactive terminal" in str(excinfo.value)


def test_confirmation_refuses_when_there_is_nothing_left_to_record(tmp_path: Path) -> None:
    rows = _rows(tmp_path)
    plan = calibrate.build_plan(rows, env={}, fixture_dir=tmp_path, already_recorded=len(rows))
    with pytest.raises(calibrate.ConfirmationError) as excinfo:
        calibrate.confirm(plan, stream=_Recorded(), reader=lambda: calibrate.CONFIRMATION_PHRASE, interactive=True)
    assert "already has a fixture" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------


def test_redaction_reaches_nested_strings_keys_and_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "shodan-key-0123456789"
    monkeypatch.setenv("SHODAN_API_KEY", secret)
    payload = {
        "url": f"https://api.shodan.io/shodan/host/1.2.3.4?key={secret}",
        "nested": {"errors": [f"HTTP 401 for https://api.shodan.io/x?key={secret}"]},
        secret: "a key used as a mapping key",
        "unrelated": 17,
    }
    cleaned = calibrate.redact_structure(payload)
    assert secret not in json.dumps(cleaned)
    assert calibrate.REDACTED in json.dumps(cleaned)
    assert cleaned["unrelated"] == 17


def test_verify_redacted_raises_when_a_credential_survives() -> None:
    secret = "abuseipdb-key-0123456789"
    with pytest.raises(calibrate.RedactionError) as excinfo:
        calibrate.verify_redacted(f"leaked {secret}", {"ABUSEIPDB_API_KEY": secret})
    assert "ABUSEIPDB_API_KEY" in str(excinfo.value)
    assert secret not in str(excinfo.value)


def test_verify_redacted_ignores_a_short_placeholder_value() -> None:
    """A blank or placeholder credential must not cause runaway substitution or a false alarm."""
    calibrate.verify_redacted("nothing to see", {"VT_API_KEY": "x"})


def test_write_fixture_refuses_to_write_a_leaked_credential(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The write is aborted, not sanitised after the fact. Nothing lands on disk."""
    secret = "otx-key-0123456789abcdef"
    monkeypatch.setenv("OTX_API_KEY", secret)
    payload = {"fixture_id": "ip-deadbeefdeadbeef", "leak": secret}
    with pytest.raises(calibrate.RedactionError):
        calibrate.write_fixture(tmp_path, payload)
    assert list((tmp_path / calibrate.RECORDS_DIRNAME).glob("*")) == []


# --------------------------------------------------------------------------------------
# The fixture envelope
# --------------------------------------------------------------------------------------


def _ip_result(indicator: str = "198.51.100.7", *, malicious: bool = True) -> Any:
    from tripper_recon.types.models import Coverage, InvestigationResult, RunMetadata

    status = {
        "virustotal": {"outcome": "ok", "elapsed_seconds": 0.4},
        "abusech": {"outcome": "ok", "elapsed_seconds": 0.2},
        "abuseipdb": {"outcome": "ok", "elapsed_seconds": 0.3},
        "otx": {"outcome": "not_configured", "elapsed_seconds": 0.0},
        "ipinfo": {"outcome": "ok", "elapsed_seconds": 0.1},
        "shodan": {"outcome": "not_found", "elapsed_seconds": 0.1},
        "rdap": {"outcome": "ok", "elapsed_seconds": 0.2},
        "cloudflare_asn": {"outcome": "ok", "elapsed_seconds": 0.2},
    }
    coverage = Coverage.from_status_map(status, expected=calibrate.IP_PROVIDERS)
    data: Dict[str, Any] = {
        "virustotal": {
            "vt_last_analysis_stats": {
                "harmless": 20,
                "malicious": 34 if malicious else 0,
                "suspicious": 4 if malicious else 0,
                "undetected": 30,
                "timeout": 0,
            },
            "vt_reputation": -80 if malicious else 3,
        },
        "abuseipdb": {
            "abuseipdb_reports": 190 if malicious else 0,
            "abuseipdb_confidence_score": 100 if malicious else 0,
        },
        "abusech": {
            "urlhaus_listed": bool(malicious),
            "urlhaus_url_count": 12 if malicious else 0,
            "abusech_source": "urlhaus",
        },
        "otx": {},
        "ipinfo": {"ip": indicator, "asn": 64500, "org": "AS64500 Example"},
        "shodan": {},
        "rdap": {},
        "asn_meta": {"asn": 64500},
        "provider_status": status,
        "coverage": coverage.model_dump(mode="json"),
    }
    return InvestigationResult(
        ok=True,
        data=data,
        coverage=coverage,
        run=RunMetadata.new(now=NOW, run_id="20260809T120000Z-testtest"),
    )


def _row(indicator: str = "198.51.100.7", *, label: str = "malicious", source: str = "urlhaus") -> Any:
    return calibrate.parse_label_row(
        {"indicator": indicator, "label": label, "label_source": source, "first_seen": "2026-05-01"}, 2
    )


def test_fixture_records_when_the_evidence_was_obtained() -> None:
    """``recorded_at`` is the whole point: a cached fact must never claim to have been queried now."""
    payload = calibrate.build_fixture(_row(), _ip_result(), now=NOW, ruleset_version="0.2.0-draft")
    assert payload["recorded_at"] == "2026-08-09T12:00:00Z"
    assert payload["schema"] == calibrate.FIXTURE_SCHEMA
    assert payload["label"] == "malicious"
    assert payload["label_source"] == "urlhaus"
    assert payload["ruleset_version_at_record"] == "0.2.0-draft"
    assert payload["recorded_by"]["run_id"] == "20260809T120000Z-testtest"


def test_fixture_keeps_the_raw_provider_payloads() -> None:
    payload = calibrate.build_fixture(_row(), _ip_result(), now=NOW, ruleset_version="v")
    assert payload["data"]["virustotal"]["vt_last_analysis_stats"]["malicious"] == 34
    assert payload["data"]["provider_status"]["otx"]["outcome"] == "not_configured"


def test_fixture_is_redacted_before_it_is_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "ipinfo-token-0123456789"
    monkeypatch.setenv("IPINFO_TOKEN", secret)
    result = _ip_result()
    result.data["errors"] = {"ipinfo": {"url": f"https://ipinfo.io/1.2.3.4?token={secret}"}}
    payload = calibrate.build_fixture(_row(), result, now=NOW, ruleset_version="v")
    path = calibrate.write_fixture(tmp_path, payload)
    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert calibrate.REDACTED in text


def test_fixture_write_is_atomic_and_leaves_no_temporary(tmp_path: Path) -> None:
    payload = calibrate.build_fixture(_row(), _ip_result(), now=NOW, ruleset_version="v")
    calibrate.write_fixture(tmp_path, payload)
    names = {path.name for path in (tmp_path / calibrate.RECORDS_DIRNAME).iterdir()}
    assert names == {f"{payload['fixture_id']}.json"}


# --------------------------------------------------------------------------------------
# Recording: pacing, resume, and failure handling -- all against a fake recorder
# --------------------------------------------------------------------------------------


class FakeRecorder:
    """Stands in for :class:`LiveRecorder`. Contacts nothing, records what it was asked."""

    def __init__(self, *, fail: Sequence[str] = (), results: Optional[Dict[str, Any]] = None) -> None:
        self.calls: List[str] = []
        self._fail = set(fail)
        self._results = results or {}

    async def investigate(self, row: Any) -> Any:
        self.calls.append(row.value)
        if row.value in self._fail:
            raise RuntimeError("provider exploded")
        return self._results.get(row.value) or _ip_result(row.value)


async def _record(rows: Sequence[Any], recorder: FakeRecorder, tmp_path: Path, **kwargs: Any) -> Any:
    sleeps: List[float] = []

    async def _sleep(seconds: float) -> None:
        sleeps.append(seconds)

    summary = await calibrate.record_all(
        rows,
        recorder=recorder,
        fixture_dir=tmp_path,
        ruleset_version="0.2.0-draft",
        sleep=_sleep,
        now=lambda: NOW,
        stream=_Recorded(),
        **kwargs,
    )
    summary.sleeps = sleeps  # type: ignore[attr-defined]
    return summary


async def test_recording_writes_a_fixture_and_a_ledger_line(tmp_path: Path) -> None:
    rows = [_row("198.51.100.7"), _row("203.0.113.9")]
    summary = await _record(rows, FakeRecorder(), tmp_path)
    assert summary.recorded == 2
    assert summary.failed == 0
    ledger = calibrate.read_ledger(tmp_path)
    assert {entry.status for entry in ledger.values()} == {"recorded"}
    assert len(list((tmp_path / calibrate.RECORDS_DIRNAME).glob("*.json"))) == 2


async def test_recording_paces_itself_between_indicators(tmp_path: Path) -> None:
    rows = [_row("198.51.100.7"), _row("203.0.113.9"), _row("192.0.2.5")]
    summary = await _record(rows, FakeRecorder(), tmp_path, min_interval=7.5)
    # One sleep fewer than indicators: nothing waits before the first call.
    assert summary.sleeps == [7.5, 7.5]


async def test_recording_resumes_and_does_not_spend_quota_twice(tmp_path: Path) -> None:
    rows = [_row("198.51.100.7"), _row("203.0.113.9")]
    first = FakeRecorder()
    await _record(rows, first, tmp_path)
    assert len(first.calls) == 2

    second = FakeRecorder()
    summary = await _record(rows, second, tmp_path)
    assert second.calls == []
    assert summary.recorded == 0
    assert summary.skipped == 2


async def test_resume_re_records_a_row_whose_fixture_file_is_missing(tmp_path: Path) -> None:
    """A ledger line without a file is an interrupted write, not a completed one."""
    rows = [_row("198.51.100.7")]
    await _record(rows, FakeRecorder(), tmp_path)
    for path in (tmp_path / calibrate.RECORDS_DIRNAME).glob("*.json"):
        path.unlink()

    recorder = FakeRecorder()
    await _record(rows, recorder, tmp_path)
    assert recorder.calls == ["198.51.100.7"]


async def test_overwrite_re_records_everything(tmp_path: Path) -> None:
    rows = [_row("198.51.100.7")]
    await _record(rows, FakeRecorder(), tmp_path)
    recorder = FakeRecorder()
    await _record(rows, recorder, tmp_path, overwrite=True)
    assert recorder.calls == ["198.51.100.7"]


async def test_a_failed_indicator_is_journalled_and_the_run_continues(tmp_path: Path) -> None:
    rows = [_row("198.51.100.7"), _row("203.0.113.9")]
    summary = await _record(rows, FakeRecorder(fail={"198.51.100.7"}), tmp_path)
    assert summary.recorded == 1
    assert summary.failed == 1
    assert summary.exit_code == calibrate.EXIT_ERROR
    ledger = calibrate.read_ledger(tmp_path)
    failed = ledger[_row("198.51.100.7").fixture_id]
    assert failed.status == "error"
    assert "provider exploded" in (failed.error or "")


async def test_a_failed_indicator_is_retried_on_the_next_run(tmp_path: Path) -> None:
    """A failure produced no evidence; skipping it on resume would silently shrink the corpus."""
    rows = [_row("198.51.100.7")]
    await _record(rows, FakeRecorder(fail={"198.51.100.7"}), tmp_path)
    recorder = FakeRecorder()
    summary = await _record(rows, recorder, tmp_path)
    assert recorder.calls == ["198.51.100.7"]
    assert summary.recorded == 1


def test_read_ledger_tolerates_a_truncated_last_line(tmp_path: Path) -> None:
    (tmp_path / calibrate.LEDGER_NAME).write_text(
        '{"fixture_id": "ip-aaaa", "status": "recorded", "at": "2026-08-09T12:00:00Z"}\n{"fixture_id": "ip-b',
        encoding="utf-8",
    )
    ledger = calibrate.read_ledger(tmp_path)
    assert set(ledger) == {"ip-aaaa"}


# --------------------------------------------------------------------------------------
# Hold-one-feed-out
# --------------------------------------------------------------------------------------


def test_feed_names_resolve_to_orchestrator_provider_keys() -> None:
    assert calibrate.resolve_held_out_providers(["urlhaus"], []) == ("abusech",)
    assert calibrate.resolve_held_out_providers(["threatfox"], []) == ("abusech",)
    assert calibrate.resolve_held_out_providers(["virustotal"], []) == ("virustotal", "virustotal_url")
    assert calibrate.resolve_held_out_providers(["urlhaus", "threatfox"], []) == ("abusech",)
    assert calibrate.resolve_held_out_providers([], ["otx"]) == ("otx",)


def test_an_unknown_feed_is_refused_rather_than_ignored() -> None:
    with pytest.raises(calibrate.CalibrationError):
        calibrate.resolve_held_out_providers(["nowhere-feed"], [])


def test_hold_out_empties_the_payload_and_marks_the_provider_skipped() -> None:
    data = _ip_result().data
    held, actually = calibrate.apply_hold_out(data, calibrate.Scope.IP, ["abusech"])
    assert held["abusech"] == {}
    assert held["provider_status"]["abusech"]["outcome"] == "skipped"
    assert actually == ["abusech"]
    # The original is untouched: hold-out never mutates the recorded evidence.
    assert data["abusech"]["urlhaus_listed"] is True


def test_hold_out_keeps_the_provider_in_the_denominator() -> None:
    """A held-out provider was applicable and deliberately not consulted. That is missing coverage.

    Zeroing a weight instead would leave it counted as having answered, inflating confidence on
    exactly the run whose purpose is to measure without it.
    """
    from tripper_recon.types.models import Coverage

    data = _ip_result().data
    before = Coverage.model_validate(data["coverage"])
    held, _ = calibrate.apply_hold_out(data, calibrate.Scope.IP, ["abusech"])
    after = Coverage.model_validate(held["coverage"])

    assert after.applicable_count == before.applicable_count
    assert "abusech" in after.skipped
    assert "abusech" not in after.answered
    assert after.answered_count == before.answered_count - 1


def test_hold_out_reports_itself_vacuous_when_the_provider_never_answered() -> None:
    data = _ip_result().data
    data["provider_status"]["abusech"] = {"outcome": "error", "elapsed_seconds": 0.1}
    _, actually = calibrate.apply_hold_out(data, calibrate.Scope.IP, ["abusech"])
    assert actually == []


def test_hold_out_coverage_matches_namespaced_names() -> None:
    from tripper_recon.types.models import Coverage

    coverage = Coverage(answered=["url:virustotal_url", "url:abusech", "198.51.100.7:otx"], not_found=["url:abusech"])
    held = calibrate._hold_out_coverage(coverage, ["abusech"])
    assert "url:abusech" in held.skipped
    assert "url:abusech" not in held.answered
    assert "url:virustotal_url" in held.answered


# --------------------------------------------------------------------------------------
# Replay and evaluation
# --------------------------------------------------------------------------------------


def _fixture(
    tmp_path: Path,
    indicator: str,
    *,
    label: str,
    source: str = "urlhaus",
    malicious: bool = True,
    first_seen: str = "2026-05-01",
    recorded_at: dt.datetime = NOW,
) -> Any:
    row = calibrate.parse_label_row(
        {"indicator": indicator, "label": label, "label_source": source, "first_seen": first_seen}, 2
    )
    payload = calibrate.build_fixture(
        row, _ip_result(indicator, malicious=malicious), now=recorded_at, ruleset_version="0.2.0-draft"
    )
    path = calibrate.write_fixture(tmp_path, payload)
    return calibrate.Fixture(path=path, payload=payload)


def _tools() -> Any:
    return calibrate.load_adjudicator(now=NOW)


def test_replay_scores_a_recorded_fixture_without_touching_the_network(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "198.51.100.7", label="malicious")
    verdict, actually_held = calibrate.replay(fixture, tools=_tools())
    assert verdict.indicator == "198.51.100.7"
    assert verdict.score > 0
    assert actually_held == []


def test_replay_with_a_feed_held_out_loses_that_feeds_signal(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "198.51.100.7", label="malicious")
    tools = _tools()
    full, _ = calibrate.replay(fixture, tools=tools)
    held, actually_held = calibrate.replay(fixture, tools=tools, held_out=["abusech"])

    assert actually_held == ["abusech"]
    assert held.score <= full.score
    full_providers = {signal.provider for signal in full.signals}
    held_providers = {signal.provider for signal in held.signals}
    assert "abusech" in full_providers
    assert "abusech" not in held_providers


def test_replay_reads_recorded_evidence_and_never_claims_freshness(tmp_path: Path) -> None:
    """The fixture says when it was recorded; the verdict says when it was evaluated. Both survive."""
    recorded = NOW - dt.timedelta(days=21)
    fixture = _fixture(tmp_path, "198.51.100.7", label="malicious", recorded_at=recorded)
    verdict, _ = calibrate.replay(fixture, tools=_tools())
    assert fixture.recorded_at == recorded
    assert verdict.evaluated_at == NOW
    assert verdict.evaluated_at != fixture.recorded_at


def _domain_result(domain: str = "evil-example.test") -> Any:
    """A domain investigation's ``data``, with abuse.ch carrying the adverse evidence."""
    from tripper_recon.types.models import Coverage, InvestigationResult, RunMetadata

    status = {
        "virustotal": {"outcome": "ok", "elapsed_seconds": 0.4},
        "otx": {"outcome": "ok", "elapsed_seconds": 0.3},
        "rdap": {"outcome": "ok", "elapsed_seconds": 0.2},
        "tranco": {"outcome": "not_found", "elapsed_seconds": 0.1},
        "abusech": {"outcome": "ok", "elapsed_seconds": 0.2},
    }
    coverage = Coverage.from_status_map(status, expected=calibrate.DOMAIN_PROVIDERS)
    data: Dict[str, Any] = {
        "domain": domain,
        "ips": [],
        "domain_provider_status": status,
        "domain_intel": {
            "virustotal": {
                "vt_last_analysis_stats": {"harmless": 40, "malicious": 12, "suspicious": 2, "undetected": 30},
                "vt_reputation": -20,
            },
            "otx": {"otx_pulse_count": 4, "otx_pulse_titles": ["Phishing kit", "Credential harvest"]},
            "rdap": {},
            "abusech": {
                "urlhaus_url_count": 9,
                "urlhaus_online": True,
                "urlhaus_payload_count": 3,
                "urlhaus_online_urls_in_response": 2,
                "urlhaus_last_online": "2026-07-20T00:00:00Z",
            },
        },
        "addresses": {"investigated": 0, "skipped": 0},
        "skipped_ips": [],
        "coverage": coverage.model_dump(mode="json"),
    }
    return InvestigationResult(
        ok=True, data=data, coverage=coverage, run=RunMetadata.new(now=NOW, run_id="20260809T120000Z-domaintest")
    )


def _url_result(url: str = "http://evil-example.test/payload.bin") -> Any:
    from tripper_recon.types.models import Coverage, InvestigationResult, RunMetadata

    status = {
        "virustotal_url": {"outcome": "ok", "elapsed_seconds": 0.4},
        "abusech": {"outcome": "ok", "elapsed_seconds": 0.2},
    }
    coverage = Coverage.from_status_map(status, expected=calibrate.URL_PROVIDERS, prefix="url:")
    data: Dict[str, Any] = {
        "url": url,
        "url_display": url,
        "url_raw": url,
        "depth": "url",
        "host": "evil-example.test",
        "url_provider_status": status,
        "url_intel": {
            "virustotal": {"vt_last_analysis_stats": {"harmless": 60, "malicious": 8}},
            "abusech": {
                "urlhaus_url": url,
                "urlhaus_url_status": "online",
                "urlhaus_online": True,
                "urlhaus_payload_count": 1,
                "urlhaus_signatures": ["Emotet"],
                "urlhaus_last_online": "2026-07-25T00:00:00Z",
            },
        },
        "ips": [],
        "collection": {"passive_only": True, "active_steps": []},
        "coverage": coverage.model_dump(mode="json"),
    }
    return InvestigationResult(
        ok=True, data=data, coverage=coverage, run=RunMetadata.new(now=NOW, run_id="20260809T120000Z-urltest")
    )


def _fixture_from(tmp_path: Path, indicator: str, result: Any, *, source: str = "urlhaus") -> Any:
    row = calibrate.parse_label_row(
        {"indicator": indicator, "label": "malicious", "label_source": source, "first_seen": "2026-06-01"}, 2
    )
    payload = calibrate.build_fixture(row, result, now=NOW, ruleset_version="0.2.0-draft")
    path = calibrate.write_fixture(tmp_path, payload)
    return calibrate.Fixture(path=path, payload=payload)


def test_domain_scope_replays_and_holds_out_the_labelling_feed(tmp_path: Path) -> None:
    fixture = _fixture_from(tmp_path, "evil-example.test", _domain_result())
    tools = _tools()
    full, _ = calibrate.replay(fixture, tools=tools)
    held, actually_held = calibrate.replay(fixture, tools=tools, held_out=["abusech"])

    assert fixture.scope is calibrate.Scope.DOMAIN
    assert actually_held == ["abusech"]
    assert "abusech" in {signal.provider for signal in full.signals}
    assert "abusech" not in {signal.provider for signal in held.signals}
    assert held.score <= full.score
    assert "abusech" in held.coverage.skipped


def test_url_scope_replays_and_holds_out_the_labelling_feed(tmp_path: Path) -> None:
    url = "http://evil-example.test/payload.bin"
    fixture = _fixture_from(tmp_path, url, _url_result(url))
    tools = _tools()
    full, _ = calibrate.replay(fixture, tools=tools)
    held, actually_held = calibrate.replay(fixture, tools=tools, held_out=["abusech"])

    assert fixture.scope is calibrate.Scope.URL
    assert actually_held == ["abusech"]
    assert full.score > 0
    assert held.score == 0
    assert "url:abusech" in held.coverage.skipped


def test_url_hold_out_does_not_shrink_the_denominator(tmp_path: Path) -> None:
    url = "http://evil-example.test/payload.bin"
    fixture = _fixture_from(tmp_path, url, _url_result(url))
    full, _ = calibrate.replay(fixture, tools=_tools())
    held, _ = calibrate.replay(fixture, tools=_tools(), held_out=["abusech"])
    assert held.coverage.applicable_count == full.coverage.applicable_count
    assert held.coverage.answered_count == full.coverage.answered_count - 1


def test_a_mixed_scope_corpus_evaluates_as_one(tmp_path: Path) -> None:
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus"),
        _fixture_from(tmp_path, "evil-example.test", _domain_result()),
        _fixture_from(tmp_path, "http://evil-example.test/payload.bin", _url_result()),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), held_out_feeds=["urlhaus"])
    assert report.evaluated == 3
    assert {row["scope"] for row in report.rows} == {"ip", "domain", "url"}
    assert report.hold_out_answering_fixtures == 3


def test_load_fixtures_rejects_a_foreign_schema(tmp_path: Path) -> None:
    _fixture(tmp_path, "198.51.100.7", label="malicious")
    stray = tmp_path / calibrate.RECORDS_DIRNAME / "stray.json"
    stray.write_text(json.dumps({"schema": "something-else/9"}), encoding="utf-8")
    fixtures, problems = calibrate.load_fixtures(tmp_path)
    assert len(fixtures) == 1
    assert any("stray.json" in problem for problem in problems)


def test_evaluation_withholds_accuracy_without_a_hold_out(tmp_path: Path) -> None:
    """The engine reads the same feeds these labels came from. That is not a measurement."""
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious"),
        _fixture(tmp_path, "203.0.113.9", label="benign", source="tranco", malicious=False),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    assert report.accuracy is None
    assert report.accuracy_withheld_reason is not None
    assert "answer key" in report.accuracy_withheld_reason
    assert report.claim == "tuned against 2 fixtures, not yet validated"


def test_the_claim_reads_as_english_for_a_single_fixture(tmp_path: Path) -> None:
    report = calibrate.evaluate_fixtures([_fixture(tmp_path, "198.51.100.7", label="malicious")], tools=_tools())
    assert report.claim == "tuned against 1 fixture, not yet validated"


def test_evaluation_withholds_accuracy_when_one_row_is_contaminated(tmp_path: Path) -> None:
    """A single row labelled by a feed still in play makes the whole figure circular."""
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus"),
        _fixture(tmp_path, "203.0.113.9", label="benign", source="tranco", malicious=False),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), held_out_feeds=["urlhaus"])
    assert report.accuracy is None
    assert report.hold_out_valid is False
    assert "tranco" in (report.accuracy_withheld_reason or "")


def test_evaluation_withholds_accuracy_when_the_hold_out_is_vacuous(tmp_path: Path) -> None:
    """Holding out a provider that never answered removes nothing. It only looks rigorous."""
    fixture = _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus")
    fixture.payload["data"]["provider_status"]["abusech"] = {"outcome": "error", "elapsed_seconds": 0.1}
    report = calibrate.evaluate_fixtures([fixture], tools=_tools(), held_out_feeds=["urlhaus"])
    assert report.accuracy is None
    assert report.hold_out_answering_fixtures == 0
    assert "removed nothing" in (report.accuracy_withheld_reason or "")


def test_evaluation_emits_accuracy_only_for_a_clean_hold_out(tmp_path: Path) -> None:
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus"),
        _fixture(tmp_path, "203.0.113.9", label="benign", source="urlhaus", malicious=False),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), held_out_feeds=["urlhaus"])
    assert report.hold_out_valid is True
    assert report.accuracy is not None
    assert 0.0 <= report.accuracy["precision"] <= 1.0
    assert 0.0 <= report.accuracy["recall"] <= 1.0
    assert "held-out precision" in report.claim


def test_evaluation_confusion_counts_are_right(tmp_path: Path) -> None:
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus"),
        _fixture(tmp_path, "203.0.113.9", label="benign", source="urlhaus", malicious=False),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    total = sum(report.confusion.values())
    assert total == 2
    assert report.evaluated == 2


def test_temporal_split_keeps_only_rows_after_the_cut(tmp_path: Path) -> None:
    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", first_seen="2026-01-01"),
        _fixture(tmp_path, "203.0.113.9", label="malicious", first_seen="2026-07-01"),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), evaluate_after=dt.datetime(2026, 6, 1, tzinfo=UTC))
    assert report.evaluated == 1
    assert report.excluded["outside_temporal_window"] == 1
    assert report.temporal_after == "2026-06-01T00:00:00Z"


def test_temporal_split_excludes_rows_with_no_first_seen(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "198.51.100.7", label="malicious")
    fixture.payload["label_first_seen"] = None
    report = calibrate.evaluate_fixtures([fixture], tools=_tools(), evaluate_after=dt.datetime(2026, 1, 1, tzinfo=UTC))
    assert report.evaluated == 0
    assert report.excluded["no_first_seen"] == 1


def test_report_always_states_the_residual_circularity(tmp_path: Path) -> None:
    """Holding out abuse.ch does not make VirusTotal an independent witness of an abuse.ch record."""
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus")]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), held_out_feeds=["urlhaus"])
    assert any("re-ingest" in caveat for caveat in report.caveats)


def test_report_warns_when_no_temporal_split_was_applied(tmp_path: Path) -> None:
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious")]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    assert any("memory, not judgement" in caveat for caveat in report.caveats)


def test_report_states_that_it_never_edits_scoring_yaml(tmp_path: Path) -> None:
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious")]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    assert any("scoring.yaml" in caveat for caveat in report.caveats)


def test_report_carries_the_age_of_the_evidence_it_rests_on(tmp_path: Path) -> None:
    recorded = NOW - dt.timedelta(days=45)
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious", recorded_at=recorded)]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    assert report.fixture_age_days["max"] == pytest.approx(45.0, abs=0.1)
    assert report.recorded_between["earliest"] == calibrate._rfc3339(recorded)
    assert any("days old" in caveat for caveat in report.caveats)


def test_rendered_report_leads_with_the_claim_the_run_earns(tmp_path: Path) -> None:
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious")]
    rendered = calibrate.render_report(calibrate.evaluate_fixtures(fixtures, tools=_tools()))
    assert "THE CLAIM THIS RUN SUPPORTS" in rendered
    assert "not yet validated" in rendered
    assert "IN-SAMPLE AGREEMENT, NOT ACCURACY" in rendered
    assert "RECORDED EVIDENCE, RE-SCORED OFFLINE" in rendered


def test_report_json_is_serialisable_and_self_describing(tmp_path: Path) -> None:
    fixtures = [_fixture(tmp_path, "198.51.100.7", label="malicious")]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools())
    payload = json.loads(json.dumps(report.to_json_dict()))
    assert payload["schema"] == calibrate.REPORT_SCHEMA
    assert payload["accuracy"] is None
    assert payload["replayed_at"]
    assert payload["rows"][0]["recorded_at"]


# --------------------------------------------------------------------------------------
# Scoring config is never touched
# --------------------------------------------------------------------------------------


def test_the_harness_imports_nothing_that_can_write_yaml() -> None:
    """Only a real held-out run may move ``calibration.status``, and only by the operator's hand."""
    tree = ast.parse(CALIBRATE_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "yaml" not in imported


def test_a_full_evaluation_leaves_the_packaged_ruleset_byte_identical(tmp_path: Path) -> None:
    """The behavioural half of the same rule: replaying cannot rewrite the thing it is grading."""
    scoring = REPO_ROOT / "tripper_recon" / "verdict" / "scoring.yaml"
    before = hashlib.sha256(scoring.read_bytes()).hexdigest()

    fixtures = [
        _fixture(tmp_path, "198.51.100.7", label="malicious", source="urlhaus"),
        _fixture(tmp_path, "203.0.113.9", label="benign", source="urlhaus", malicious=False),
    ]
    report = calibrate.evaluate_fixtures(fixtures, tools=_tools(), held_out_feeds=["urlhaus"])
    calibrate.render_report(report)
    json.dumps(report.to_json_dict())

    assert hashlib.sha256(scoring.read_bytes()).hexdigest() == before


def test_packaged_ruleset_is_still_unvalidated() -> None:
    """A guard on the deliverable's own premise: no run has happened, so the status must not have moved."""
    from tripper_recon.verdict.config import CalibrationStatus, default_config

    config = default_config()
    assert config.calibration.status is CalibrationStatus.UNVALIDATED
    assert config.calibration.precision is None
    assert config.calibration.recall is None
