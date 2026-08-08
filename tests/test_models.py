"""Tests for the W4 data models: ProviderStatus, Coverage, RunMetadata, SkippedAddress.

The bug these models exist to prevent is not a crash. It is a correct-looking screen: with two
of six credentials configured the tool showed one VirusTotal score and one Shodan error and
said nothing at all about the four providers nobody asked. The tests below are therefore
mostly assertions about *absence* -- that nothing known never computes as everything clean,
that an unconfigured provider stays in the denominator, and that a refused address survives
into the output instead of vanishing.

No network, no credentials, no orchestrator: these are pure model tests.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from tripper_recon import __version__
from tripper_recon.types.models import (
    Coverage,
    InvestigationResult,
    ProviderCall,
    ProviderOutcome,
    ProviderStatus,
    RunMetadata,
    SkippedAddress,
    SkipReason,
    coverage_from_result_data,
    current_run,
    reset_run,
    skipped_addresses_from_data,
)

# --------------------------------------------------------------------------------------
# ProviderStatus
# --------------------------------------------------------------------------------------


def test_status_wire_values_match_what_the_orchestrator_already_emits() -> None:
    """``_status_map`` writes these three strings today; renaming them would break -o json."""
    assert ProviderStatus.OK.value == "ok"
    assert ProviderStatus.ERROR.value == "error"
    assert ProviderStatus.NOT_CONFIGURED.value == "not_configured"
    assert ProviderStatus.NOT_FOUND.value == "not_found"
    assert ProviderStatus.SKIPPED.value == "skipped"


def test_provider_outcome_is_the_same_class_not_a_copy() -> None:
    """orchestrators imports ProviderOutcome. An alias cannot drift; a second enum would."""
    assert ProviderOutcome is ProviderStatus
    assert ProviderOutcome.OK is ProviderStatus.OK


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("answered", ProviderStatus.OK),
        ("ANSWERED", ProviderStatus.OK),
        ("ok", ProviderStatus.OK),
        ("not-found", ProviderStatus.NOT_FOUND),
        ("not_found", ProviderStatus.NOT_FOUND),
        (" not_configured ", ProviderStatus.NOT_CONFIGURED),
    ],
)
def test_status_accepts_roadmap_spellings(raw: str, expected: ProviderStatus) -> None:
    assert ProviderStatus(raw) is expected


@pytest.mark.parametrize("raw", ["clean", "", "unknown", "success", None, 3])
def test_status_refuses_to_guess_at_an_unknown_outcome(raw: object) -> None:
    """Mapping an unrecognised outcome onto a known one is the exact bug class this prevents."""
    with pytest.raises(ValueError):
        ProviderStatus(raw)


def test_observation_and_missing_coverage_are_exact_complements() -> None:
    for status in ProviderStatus:
        assert status.is_observation != status.is_missing_coverage
    assert ProviderStatus.OK.is_observation
    assert ProviderStatus.NOT_FOUND.is_observation
    assert ProviderStatus.NOT_CONFIGURED.is_missing_coverage
    assert ProviderStatus.ERROR.is_missing_coverage
    assert ProviderStatus.SKIPPED.is_missing_coverage


def test_provider_call_still_reports_ok_only_for_ok() -> None:
    assert ProviderCall(provider="virustotal", outcome=ProviderStatus.OK).ok is True
    assert ProviderCall(provider="virustotal", outcome=ProviderStatus.NOT_CONFIGURED).ok is False
    assert ProviderCall(provider="virustotal", outcome=ProviderStatus.NOT_FOUND).ok is False


# --------------------------------------------------------------------------------------
# Coverage -- the central semantic
# --------------------------------------------------------------------------------------


def _two_of_six() -> Dict[str, Dict[str, Any]]:
    """The verified real-world case: two credentials configured, six providers intended."""
    return {
        "virustotal": {"outcome": "ok", "elapsed_seconds": 0.4},
        "shodan": {"outcome": "error", "elapsed_seconds": 0.2, "error": {"error": "http_error", "status": 401}},
        "ipinfo": {"outcome": "not_configured", "elapsed_seconds": 0.0},
        "abuseipdb": {"outcome": "not_configured", "elapsed_seconds": 0.0},
        "otx": {"outcome": "not_configured", "elapsed_seconds": 0.0},
        "cloudflare_asn": {"outcome": "not_configured", "elapsed_seconds": 0.0},
    }


def test_unconfigured_providers_stay_in_the_denominator() -> None:
    """A provider with no API key is MISSING COVERAGE, not an excuse.

    The failure mode: counting only the providers that were configured, so a run with one
    working credential reports 1 of 1 and the analyst reads full coverage.
    """
    coverage = Coverage.from_status_map(_two_of_six())

    assert coverage.answered == ["virustotal"]
    assert coverage.unconfigured == ["ipinfo", "abuseipdb", "otx", "cloudflare_asn"]
    assert coverage.applicable_count == 6
    assert coverage.answered_count == 1
    assert coverage.ratio == pytest.approx(1 / 6, abs=1e-4)
    assert coverage.is_complete is False
    assert coverage.headline == "1 of 6 providers answered"


def test_missing_lists_every_provider_that_contributed_nothing() -> None:
    coverage = Coverage.from_status_map(_two_of_six())
    assert coverage.missing == ["shodan", "ipinfo", "abuseipdb", "otx", "cloudflare_asn"]


def test_empty_coverage_is_zero_not_one() -> None:
    """Nothing asked is never everything clean, and the zero denominator does not raise."""
    coverage = Coverage()
    assert coverage.ratio == 0.0
    assert coverage.applicable_count == 0
    assert coverage.is_complete is False
    assert coverage.is_sufficient() is False
    assert coverage.is_sufficient(0.0) is False  # even a floor of zero must not pass an empty run
    assert coverage.headline == "0 of 0 providers answered"


def test_all_unconfigured_is_zero_coverage_not_complete() -> None:
    coverage = Coverage.from_status_map({name: {"outcome": "not_configured"} for name in ("vt", "shodan", "otx")})
    assert coverage.answered == []
    assert coverage.ratio == 0.0
    assert coverage.is_complete is False
    assert coverage.headline == "0 of 3 providers answered"


def test_not_found_counts_as_answered_and_is_recorded_separately() -> None:
    """A "no record held" answer is an observation; "never asked" is not. Keep them distinct."""
    coverage = Coverage.from_status_map(
        {
            "virustotal": {"outcome": "ok"},
            "shodan": {"outcome": "not_found"},
            "otx": {"outcome": "not_configured"},
        }
    )
    assert coverage.answered == ["virustotal", "shodan"]
    assert coverage.not_found == ["shodan"]
    assert coverage.answered_count == 2
    assert coverage.ratio == pytest.approx(2 / 3, abs=1e-4)


def test_full_coverage_is_reachable() -> None:
    coverage = Coverage.from_status_map({name: {"outcome": "ok"} for name in ("vt", "shodan")})
    assert coverage.ratio == 1.0
    assert coverage.is_complete is True
    assert coverage.missing == []
    assert coverage.is_sufficient(1.0) is True


def test_expected_providers_absent_from_the_map_are_counted_as_skipped() -> None:
    """A provider that was never even attempted must not quietly shrink the denominator."""
    coverage = Coverage.from_status_map(
        {"virustotal": {"outcome": "ok"}},
        expected=["virustotal", "shodan", "otx"],
    )
    assert coverage.skipped == ["shodan", "otx"]
    assert coverage.applicable_count == 3
    assert coverage.headline == "1 of 3 providers answered"


def test_unreadable_outcome_is_filed_as_an_error_not_as_an_answer() -> None:
    """An outcome nobody can interpret is not evidence. Conservative bucket, by design."""
    coverage = Coverage.from_status_map(
        {
            "virustotal": {"outcome": "ok"},
            "shodan": {"outcome": "banana"},
            "otx": {"elapsed_seconds": 0.1},
            "ipinfo": "not-even-a-mapping",  # type: ignore[dict-item]
        }
    )
    assert coverage.answered == ["virustotal"]
    assert set(coverage.errored) == {"shodan", "otx", "ipinfo"}
    assert coverage.applicable_count == 4


def test_suppressed_failures_still_count_as_missing_coverage() -> None:
    """Suppression is a rendering decision. It must not become a coverage decision."""
    coverage = Coverage.from_status_map(
        {
            "virustotal": {"outcome": "ok"},
            "ipinfo_asn": {"outcome": "error", "suppressed": True, "error": {"error": "unauthorized"}},
        }
    )
    assert coverage.errored == ["ipinfo_asn"]
    assert coverage.ratio == 0.5


def test_prefix_namespaces_provider_names_for_merging() -> None:
    coverage = Coverage.from_status_map({"virustotal": {"outcome": "ok"}}, prefix="1.2.3.4:")
    assert coverage.answered == ["1.2.3.4:virustotal"]


def test_conflicts_resolve_toward_less_coverage() -> None:
    """The same name answered and errored can only under-state, never over-state, coverage."""
    coverage = Coverage(answered=["vt", "shodan"], errored=["vt"])
    assert coverage.answered == ["shodan"]
    assert coverage.errored == ["vt"]
    assert coverage.applicable_count == 2
    assert coverage.ratio == 0.5


def test_not_found_is_pruned_to_the_answered_subset() -> None:
    coverage = Coverage(answered=["vt"], not_found=["vt", "ghost"])
    assert coverage.not_found == ["vt"]


def test_buckets_are_deduped_without_reordering() -> None:
    coverage = Coverage(answered=["b", "a", "b"], unconfigured=["c", "c"])
    assert coverage.answered == ["b", "a"]
    assert coverage.unconfigured == ["c"]
    assert coverage.applicable_count == 3


def test_merge_unions_the_buckets() -> None:
    merged = Coverage.merge(
        [
            Coverage.from_status_map({"vt": {"outcome": "ok"}}, prefix="a:"),
            Coverage.from_status_map({"vt": {"outcome": "not_configured"}}, prefix="b:"),
        ]
    )
    assert merged.answered == ["a:vt"]
    assert merged.unconfigured == ["b:vt"]
    assert merged.headline == "1 of 2 providers answered"


def test_merge_of_nothing_is_empty_not_complete() -> None:
    merged = Coverage.merge([])
    assert merged.ratio == 0.0
    assert merged.is_complete is False


@pytest.mark.parametrize(
    ("answered", "total", "floor", "expected"),
    [
        (1, 6, 0.5, False),
        (3, 6, 0.5, True),
        (2, 6, 0.5, False),
        (6, 6, 1.0, True),
        (5, 6, 1.0, False),
    ],
)
def test_is_sufficient_implements_the_confidence_floor(answered: int, total: int, floor: float, expected: bool) -> None:
    """W5.4: confidence is forced LOW below the coverage floor. This is the predicate for it."""
    status: Dict[str, Dict[str, Any]] = {f"p{i}": {"outcome": "ok"} for i in range(answered)}
    status.update({f"p{i}": {"outcome": "not_configured"} for i in range(answered, total)})
    assert Coverage.from_status_map(status).is_sufficient(floor) is expected


def test_coverage_serialises_with_its_computed_fields() -> None:
    """-o json must carry the ratio and the headline, not just the raw lists."""
    payload = json.loads(Coverage.from_status_map(_two_of_six()).model_dump_json())
    assert payload["answered"] == ["virustotal"]
    assert payload["answered_count"] == 1
    assert payload["applicable_count"] == 6
    assert payload["headline"] == "1 of 6 providers answered"
    assert payload["ratio"] < 0.2
    assert payload["is_complete"] is False


# --------------------------------------------------------------------------------------
# coverage_from_result_data -- the wiring helper for each orchestrator shape
# --------------------------------------------------------------------------------------


def test_coverage_from_ip_result_shape() -> None:
    coverage = coverage_from_result_data({"provider_status": _two_of_six()})
    assert coverage.headline == "1 of 6 providers answered"


def test_coverage_from_domain_result_shape_namespaces_each_address() -> None:
    data: Dict[str, Any] = {
        "domain": "example.com",
        "domain_provider_status": {"virustotal": {"outcome": "ok"}, "otx": {"outcome": "not_configured"}},
        "ips": [
            {"ip": "203.0.113.10", "provider_status": {"virustotal": {"outcome": "ok"}}},
            {"ip": "203.0.113.11", "provider_status": {"virustotal": {"outcome": "error"}}},
        ],
    }
    coverage = coverage_from_result_data(data)
    assert coverage.answered == ["domain:virustotal", "203.0.113.10:virustotal"]
    assert coverage.unconfigured == ["domain:otx"]
    assert coverage.errored == ["203.0.113.11:virustotal"]
    assert coverage.applicable_count == 4


def test_coverage_from_result_data_tolerates_a_missing_status_map() -> None:
    coverage = coverage_from_result_data({"ips": [{"ip": "203.0.113.10"}], "domain": "example.com"})
    assert coverage.applicable_count == 0
    assert coverage.is_complete is False


# --------------------------------------------------------------------------------------
# SkippedAddress -- the addresses that currently vanish
# --------------------------------------------------------------------------------------


def test_skipped_address_parses_the_orchestrator_entry_shape() -> None:
    """``data['skipped_ips']`` entries are ``{'ip', 'source', 'reason'}`` today."""
    skipped = SkippedAddress.from_mapping({"ip": "10.0.0.5", "source": "active", "reason": "private"})
    assert skipped.address == "10.0.0.5"
    assert skipped.reason is SkipReason.PRIVATE
    assert skipped.source == "active"
    assert skipped.detail is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("private", SkipReason.PRIVATE),
        ("loopback", SkipReason.LOOPBACK),
        ("link-local", SkipReason.LINK_LOCAL),
        ("link_local", SkipReason.LINK_LOCAL),
        ("Link-Local", SkipReason.LINK_LOCAL),
        ("multicast", SkipReason.MULTICAST),
        ("reserved", SkipReason.RESERVED),
        ("unspecified", SkipReason.UNSPECIFIED),
    ],
)
def test_skip_reason_covers_every_non_public_category(raw: str, expected: SkipReason) -> None:
    """One member per entry in ``orchestrators._NON_PUBLIC_CATEGORIES``, lowercased as emitted."""
    assert SkipReason(raw) is expected


def test_skipped_address_preserves_an_explicit_detail() -> None:
    """orchestrators writes a full sentence into ``detail``; parsing must not discard it."""
    skipped = SkippedAddress.from_mapping(
        {
            "ip": "10.0.0.5",
            "source": "active",
            "reason": "private",
            "detail": "private addressing is never sent to a third-party provider",
        }
    )
    assert skipped.reason is SkipReason.PRIVATE
    assert skipped.detail == "private addressing is never sent to a third-party provider"


def test_unknown_skip_reason_falls_back_but_keeps_the_original_wording() -> None:
    skipped = SkippedAddress.from_mapping({"ip": "192.0.2.9", "reason": "quarantined by policy"})
    assert skipped.reason is SkipReason.OTHER
    assert skipped.detail == "quarantined by policy"
    assert "quarantined by policy" in skipped.explanation


def test_skipped_address_explanation_names_the_address_and_the_reason() -> None:
    skipped = SkippedAddress(address="10.0.0.5", reason=SkipReason.PRIVATE, source="active")
    assert skipped.explanation == (
        "10.0.0.5 (active) was not investigated: private addressing is never sent to a provider"
    )


def test_skipped_address_explanation_serialises() -> None:
    payload = json.loads(SkippedAddress(address="10.0.0.5", reason=SkipReason.PRIVATE).model_dump_json())
    assert payload["address"] == "10.0.0.5"
    assert payload["reason"] == "private"
    assert "was not investigated" in payload["explanation"]


def test_skipped_addresses_from_data_parses_the_whole_list() -> None:
    entries = [
        {"ip": "10.0.0.1", "source": "active", "reason": "private"},
        {"ip": "127.0.0.1", "source": "passive", "reason": "loopback"},
        {"ip": "224.0.0.1", "source": "active", "reason": "multicast"},
    ]
    parsed = skipped_addresses_from_data(entries)
    assert [s.address for s in parsed] == ["10.0.0.1", "127.0.0.1", "224.0.0.1"]
    assert [s.reason for s in parsed] == [SkipReason.PRIVATE, SkipReason.LOOPBACK, SkipReason.MULTICAST]


def test_skipped_addresses_from_data_handles_absent_and_malformed_input() -> None:
    assert skipped_addresses_from_data(None) == []
    assert skipped_addresses_from_data([]) == []
    assert skipped_addresses_from_data(["not a mapping"]) == []  # type: ignore[list-item]


# --------------------------------------------------------------------------------------
# RunMetadata
# --------------------------------------------------------------------------------------


def test_run_metadata_carries_the_package_version() -> None:
    """__version__ existed and never reached output. This is the wire that connects it."""
    assert RunMetadata.new().tool_version == __version__


def test_started_at_is_timezone_aware_utc() -> None:
    run = RunMetadata.new()
    assert run.started_at.tzinfo is not None
    assert run.started_at.utcoffset() == timedelta(0)


def test_naive_timestamps_are_rejected_not_assumed_to_be_utc() -> None:
    """Assuming a naive datetime is UTC is how a report acquires a silently wrong timestamp."""
    with pytest.raises(ValidationError):
        RunMetadata(run_id="r", started_at=datetime(2026, 8, 8, 12, 0, 0))
    with pytest.raises(ValueError):
        RunMetadata.new(now=datetime(2026, 8, 8, 12, 0, 0))


def test_offset_timestamps_are_normalised_to_utc() -> None:
    run = RunMetadata.new(now=datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone(timedelta(hours=-4))), run_id="r")
    assert run.started_at == datetime(2026, 8, 8, 16, 0, 0, tzinfo=timezone.utc)
    assert run.started_at_rfc3339 == "2026-08-08T16:00:00Z"


def test_timestamp_serialises_as_rfc3339_in_both_dump_modes() -> None:
    """python-mode dumps go straight to rich.print_json, which cannot serialise a datetime."""
    run = RunMetadata.new(now=datetime(2026, 8, 8, 16, 0, 0, tzinfo=timezone.utc), run_id="r")
    assert run.model_dump()["started_at"] == "2026-08-08T16:00:00Z"
    assert json.loads(run.model_dump_json())["started_at"] == "2026-08-08T16:00:00Z"
    json.dumps(run.model_dump())  # would raise TypeError if a datetime survived the dump


def test_run_id_is_unique_per_run_and_sorts_by_time() -> None:
    first = RunMetadata.new(now=datetime(2026, 8, 8, 16, 0, 0, tzinfo=timezone.utc))
    second = RunMetadata.new(now=datetime(2026, 8, 8, 17, 0, 0, tzinfo=timezone.utc))
    assert first.run_id != second.run_id
    assert first.run_id.startswith("20260808T160000Z-")
    assert first.run_id < second.run_id


def test_current_run_is_one_run_shared_by_every_target() -> None:
    """Deterministic per run: a bulk run's forty results all correlate to one another."""
    reset_run()
    try:
        assert current_run() is current_run()
        assert current_run().run_id == current_run().run_id
    finally:
        reset_run()


def test_reset_run_starts_a_new_run() -> None:
    first = reset_run()
    second = reset_run()
    assert first.run_id != second.run_id
    assert current_run() is second
    reset_run()


# --------------------------------------------------------------------------------------
# InvestigationResult
# --------------------------------------------------------------------------------------


def test_existing_construction_sites_keep_working() -> None:
    """Every orchestrator return statement passes ok/data/warnings/errors and nothing else."""
    result = InvestigationResult(ok=False, errors=["Invalid IP address"], data={})
    assert result.run is None
    assert result.coverage is None
    assert result.skipped_addresses == []


def test_uncomputed_coverage_reads_as_zero_never_as_clean() -> None:
    """The accessor the verdict engine uses. None must not become "everything answered"."""
    result = InvestigationResult(ok=True)
    assert result.coverage is None
    assert result.coverage_or_unknown.ratio == 0.0
    assert result.coverage_or_unknown.is_complete is False
    assert result.coverage_or_unknown.is_sufficient() is False


def test_coverage_or_unknown_returns_real_coverage_when_present() -> None:
    coverage = Coverage.from_status_map({"vt": {"outcome": "ok"}})
    result = InvestigationResult(ok=True, coverage=coverage)
    assert result.coverage_or_unknown is coverage


def test_with_run_stamps_the_current_run_without_mutating_the_original() -> None:
    reset_run()
    try:
        result = InvestigationResult(ok=True)
        stamped = result.with_run()
        assert result.run is None
        assert stamped.run is not None
        assert stamped.run.run_id == current_run().run_id
    finally:
        reset_run()


def test_full_result_round_trips_through_json() -> None:
    """Everything W4 adds has to survive ``-o json``; that is why they are pydantic models."""
    data = {"provider_status": _two_of_six()}
    result = InvestigationResult(
        ok=True,
        data=data,
        coverage=coverage_from_result_data(data),
        skipped_addresses=skipped_addresses_from_data([{"ip": "10.0.0.1", "source": "active", "reason": "private"}]),
    ).with_run(RunMetadata.new(now=datetime(2026, 8, 8, 16, 0, 0, tzinfo=timezone.utc), run_id="r-1"))

    payload = json.loads(json.dumps(result.model_dump()))

    assert payload["run"]["run_id"] == "r-1"
    assert payload["run"]["tool_version"] == __version__
    assert payload["run"]["started_at"] == "2026-08-08T16:00:00Z"
    assert payload["coverage"]["headline"] == "1 of 6 providers answered"
    assert payload["coverage"]["unconfigured"] == ["ipinfo", "abuseipdb", "otx", "cloudflare_asn"]
    assert payload["skipped_addresses"][0]["address"] == "10.0.0.1"
    assert payload["skipped_addresses"][0]["reason"] == "private"

    restored = InvestigationResult.model_validate(payload)
    assert restored.coverage is not None
    assert restored.coverage.ratio == result.coverage_or_unknown.ratio
    assert restored.skipped_addresses[0].reason is SkipReason.PRIVATE
    assert restored.run is not None
    assert restored.run.started_at == datetime(2026, 8, 8, 16, 0, 0, tzinfo=timezone.utc)
