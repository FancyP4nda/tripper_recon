"""Unit and integration tests for the TTL cache and the case directory (roadmap 7.7).

**Everything here defends one sentence: a cached fact must never claim to have been queried
now.** The tests are grouped by the mechanisms that make that true, and each group states the
failure it exists to catch:

* **Ruleset** -- a misspelled provider key silently inheriting a long default lifetime.
* **Keys** -- two different questions sharing one entry, or one question missing its own.
* **Store** -- an expired, undated, corrupt or future-schema entry being replayed as current.
* **Session** -- a replay happening without being recorded anywhere a reader will look.
* **Freshness** -- "8 of 8 answered" being true of a run that queried nothing at all.
* **Offline** -- a stale value served because it was nearly fresh and right there.
* **Case** -- a report regenerated months later acquiring the regeneration's timestamps.

**Network:** nothing here touches it, and two tests prove that as their assertion rather than
assuming it. ``tests/conftest.no_real_network`` installs an outer respx router with no routes, so
any request raises ``AllMockedAssertionError``. The ``--offline`` tests register no routes of
their own **on purpose**: if the offline path ever reaches a socket, the test fails loudly rather
than quietly spending the operator's quota.
"""

from __future__ import annotations

import datetime as dt
import gc
import json
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from pydantic import ValidationError

from tripper_recon import __version__, orchestrators
from tripper_recon.orchestrators import SCOPE_ASN, SCOPE_DOMAIN, SCOPE_IP, investigate_domain, investigate_ip
from tripper_recon.utils.cache import (
    CACHE_CONFIG_ENV_VAR,
    CACHE_ENTRY_SCHEMA,
    CASE_SCHEMA,
    CacheConfig,
    CacheConfigError,
    CacheEntry,
    CacheError,
    CacheSession,
    CacheState,
    CacheStore,
    active_cache,
    cache_key,
    case_id_for,
    clear_cache_config_cache,
    default_cache_config,
    default_cache_root,
    default_case_root,
    format_age,
    freshness_warnings,
    load_cache_config,
    load_case,
    parse_duration,
    summarise_freshness,
    use_cache,
    write_case,
)

NOW = dt.datetime(2026, 8, 9, 12, 0, 0, tzinfo=dt.timezone.utc)


def _stamp(offset_seconds: float) -> dt.datetime:
    """A timestamp ``offset_seconds`` before :data:`NOW`."""
    return NOW - dt.timedelta(seconds=offset_seconds)


@pytest.fixture
def store(tmp_path: Path) -> CacheStore:
    """A cache rooted in a temp directory, with lifetimes pinned rather than inherited.

    Pinned because the packaged ruleset is policy that will change: a test asserting staleness
    against ``cache.yaml``'s live value would start failing the day somebody shortens a TTL for
    a good reason.
    """
    return CacheStore(tmp_path / "cache", config=CacheConfig(default_ttl_seconds=3600, providers={"rdap": 604800}))


@pytest.fixture(autouse=True)
def _reset_config_cache() -> Any:
    """The ruleset is memoised per process; a test that changes the environment must not leak."""
    clear_cache_config_cache()
    yield
    clear_cache_config_cache()


# --------------------------------------------------------------------------------------
# The TTL ruleset
# --------------------------------------------------------------------------------------


def test_packaged_ruleset_loads_and_names_itself() -> None:
    """The shipped ``cache.yaml`` parses, and says where it came from.

    ``source_origin`` is not decoration: "the operator has a stale override in ~/.config" is
    otherwise an unfalsifiable explanation for a lifetime nobody expected.
    """
    config = default_cache_config()

    assert config.enabled is True
    assert config.default_ttl_seconds > 0
    assert "cache.yaml" in config.source_label


def test_registration_data_outlives_reputation_data() -> None:
    """The whole point of a PER-PROVIDER lifetime, asserted as a relationship not a number.

    A domain's registration date does not move for months and an abuse feed moves in minutes.
    Pinning the exact seconds would make this test a change-detector; pinning the ordering makes
    it a policy check that survives a deliberate retune.
    """
    config = default_cache_config()

    assert config.ttl_for("rdap") > config.ttl_for("virustotal")
    assert config.ttl_for("abusech") <= config.ttl_for("virustotal")
    assert config.ttl_for("dns") < config.ttl_for("abusech")


def test_an_unknown_provider_gets_the_short_default_not_a_guess() -> None:
    """Guessing long about a provider nobody configured is the failure mode to avoid."""
    config = CacheConfig(default_ttl_seconds=600, providers={"rdap": 604800})

    assert config.ttl_for("a-provider-that-does-not-exist") == 600


def test_a_misspelled_key_is_a_load_error_not_a_silent_default(tmp_path: Path) -> None:
    """``extra="forbid"``. Otherwise ``abuse_ch:`` typed for ``abusech:`` gives a feed a 1h TTL
    it was never meant to have, and nothing anywhere says so."""
    path = tmp_path / "cache.yaml"
    path.write_text(
        "schema_version: tripper-recon.cache-config/1\nproviders:\n  rdap: 60\nprovider_ttls:\n  rdap: 60\n",
        encoding="utf-8",
    )

    with pytest.raises(CacheConfigError):
        load_cache_config(path)


def test_an_explicit_ruleset_that_does_not_exist_is_an_error(tmp_path: Path) -> None:
    """Never a silent fallback: the operator asked for a specific policy."""
    with pytest.raises(CacheConfigError, match="does not exist"):
        load_cache_config(tmp_path / "absent.yaml")


def test_the_env_var_selects_a_ruleset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "cache.yaml"
    path.write_text(
        "schema_version: tripper-recon.cache-config/1\ndefault_ttl_seconds: 42\nproviders: {}\n", encoding="utf-8"
    )
    monkeypatch.setenv(CACHE_CONFIG_ENV_VAR, str(path))

    assert load_cache_config().default_ttl_seconds == 42


def test_a_future_ruleset_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "cache.yaml"
    path.write_text("schema_version: tripper-recon.cache-config/9\nproviders: {}\n", encoding="utf-8")

    with pytest.raises(CacheConfigError, match="schema"):
        load_cache_config(path)


# --------------------------------------------------------------------------------------
# Durations and ages
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("0", 0.0), ("30", 30.0), ("90s", 90.0), ("15m", 900.0), ("6h", 21600.0), ("7d", 604800.0), ("2w", 1209600.0)],
)
def test_durations_parse(text: str, seconds: float) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "soon", "-5m", "5 fortnights", "1.2.3"])
def test_an_unreadable_duration_is_refused_not_defaulted(text: str) -> None:
    """A guessed ``--max-age`` is a freshness guarantee the operator never made."""
    with pytest.raises(ValueError):
        parse_duration(text)


def test_an_unknown_age_renders_as_unknown_not_zero() -> None:
    """``0s`` reads as "just now", which is the one thing an uncomputable age must not say."""
    assert format_age(None) == "unknown"
    assert format_age(41 * 60) == "41m"
    assert format_age(90000) == "1d 1h"


# --------------------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------------------


def test_the_key_is_stable_for_the_same_question() -> None:
    first = cache_key(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8")
    second = cache_key(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8")

    assert first == second


@pytest.mark.parametrize(
    "changed",
    [
        {"provider": "shodan"},
        {"scope": SCOPE_DOMAIN},
        {"indicator": "8.8.4.4"},
        {"tool_version": "99.0.0"},
    ],
)
def test_every_component_of_the_key_changes_it(changed: Dict[str, str]) -> None:
    """Each of the four is in the key because it can change the answer.

    ``tool_version`` is the least obvious and the most important: a provider module's extraction
    shape can change between releases, and replaying a payload shaped for the previous parser is
    a stale answer wearing a current schema.
    """
    base = {"provider": "virustotal", "scope": SCOPE_IP, "indicator": "8.8.8.8"}

    assert cache_key(**{**base, **changed}) != cache_key(**base)  # type: ignore[arg-type]


def test_the_paid_and_keyless_exposure_lookups_do_not_share_an_entry() -> None:
    """InternetDB is a strict subset of the paid Shodan record -- it drops the banners, the
    network owner and ``last_update``. One entry for both would let a keyless run's thinner
    answer be replayed to a key-holding operator as though it were what they paid for."""
    paid = cache_key(provider="shodan", scope=SCOPE_IP, indicator="8.8.8.8")
    keyless = cache_key(provider="internetdb", scope=SCOPE_IP, indicator="8.8.8.8")

    assert paid != keyless


# --------------------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------------------


def test_a_stored_answer_round_trips_with_its_original_query_time(store: CacheStore) -> None:
    """THE CENTRAL ASSERTION OF THIS FILE.

    The replayed entry reports the instant the request actually left -- twenty minutes before
    ``now`` -- not the instant it was replayed. Every other honesty control in the package is
    downstream of this one value surviving a round trip unaltered.
    """
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {"vt_reputation": 7}},
        queried_at=_stamp(1200),
        now=_stamp(1200),
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.state is CacheState.HIT
    assert lookup.entry is not None
    assert lookup.entry.queried_at == "2026-08-09T11:40:00Z"
    assert lookup.entry.payload == {"ok": True, "data": {"vt_reputation": 7}}
    assert lookup.age_seconds == pytest.approx(1200.0)
    assert "20m ago" in lookup.reason


def test_an_expired_entry_is_stale_and_is_never_a_hit(store: CacheStore) -> None:
    """Past its lifetime is past its lifetime. There is no "close enough" branch."""
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {}},
        queried_at=_stamp(7200),
        now=_stamp(7200),
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.state is CacheState.STALE
    assert lookup.is_hit is False
    assert "past its" in lookup.reason


def test_an_entry_stamped_in_the_future_is_refused_not_served_as_brand_new(store: CacheStore) -> None:
    """A future ``queried_at`` is the module's own rule failing in the one forbidden direction.

    The age arithmetic clamps at zero, so before this was fixed an entry stamped forty days
    ahead came back as ``HIT`` with ``age_seconds == 0.0`` and the reason "obtained 0s ago" --
    the strongest freshness claim the tool can make, manufactured out of a wrong clock. It also
    defeated ``--max-age`` completely, because nothing is older than a limit when everything
    reports zero.

    Causes are mundane: a cache directory copied from another host, a VM resuming with a stepped
    clock, an edited file. The response is the same one an undated entry gets -- discard it.
    """
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {"vt_malicious": 99}},
        queried_at=NOW + dt.timedelta(days=40),
        now=NOW,
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.state is CacheState.DISABLED
    assert lookup.is_hit is False
    assert "FUTURE" in lookup.reason
    # And the flag that a future stamp used to walk straight past.
    assert (
        store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW, max_age_seconds=60).is_hit
        is False
    )


def test_a_few_seconds_of_clock_skew_does_not_flush_the_cache(store: CacheStore) -> None:
    """The tolerance earns its place: NTP stepping backwards a second is not an integrity event.

    Refusing on ordinary jitter would send every provider back to the network for no gain, which
    is the cost this cache exists to avoid. Only skew large enough to be a real freshness claim
    is treated as one.
    """
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {}},
        queried_at=NOW + dt.timedelta(seconds=2),
        now=NOW,
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.state is CacheState.HIT
    assert lookup.age_seconds == pytest.approx(0.0)


def test_max_age_is_distinguished_from_expiry(store: CacheStore) -> None:
    """``STALE`` and ``TOO_OLD`` both refuse, and an analyst debugging a surprise network call
    deserves to know which of the two -- the ruleset or their own flag -- caused it."""
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {}},
        queried_at=_stamp(1800),
        now=_stamp(1800),
    )

    within_ttl = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)
    demanded_fresher = store.get(
        provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW, max_age_seconds=900
    )

    assert within_ttl.state is CacheState.HIT
    assert demanded_fresher.state is CacheState.TOO_OLD
    assert "--max-age" in demanded_fresher.reason


def test_max_age_zero_means_query_everything_now(store: CacheStore) -> None:
    """The escape hatch the freshness warning tells the operator about has to actually work."""
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {}},
        queried_at=_stamp(1),
        now=_stamp(1),
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW, max_age_seconds=0)

    assert lookup.state is CacheState.TOO_OLD


def test_failures_are_never_cached(store: CacheStore) -> None:
    """An error is a state of the world at one instant. Replaying a 429, an unset key or a
    network blip would turn a transient outage into a persistent one that outlives its cause."""
    stored = store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": False, "error": "http_error", "status_code": 429},
        queried_at=NOW,
        now=NOW,
    )

    assert stored is None
    assert store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW).state is CacheState.MISS


def test_an_entry_with_no_readable_query_time_is_discarded(store: CacheStore, tmp_path: Path) -> None:
    """An answer that cannot say when it was obtained is precisely the artefact this module
    exists to prevent. It is thrown away, never trusted."""
    key = cache_key(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8")
    path = store.path_for(provider="virustotal", scope=SCOPE_IP, key=key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": CACHE_ENTRY_SCHEMA,
                "provider": "virustotal",
                "scope": SCOPE_IP,
                "indicator": "8.8.8.8",
                "key": key,
                "tool_version": __version__,
                "queried_at": "not a timestamp",
                "stored_at": "2026-08-09T12:00:00Z",
                "ttl_seconds": 3600,
                "payload": {"ok": True, "data": {"vt_reputation": 7}},
            }
        ),
        encoding="utf-8",
    )

    lookup = store.get(provider="virustotal", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.state is CacheState.DISABLED
    assert "queried_at" in lookup.reason


@pytest.mark.parametrize(
    ("content", "fragment"),
    [
        ("{ not json", "could not be read"),
        ('{"schema_version": "tripper-recon.cache-entry/9"}', "schema"),
        ("[]", "not an object"),
    ],
)
def test_an_unusable_entry_degrades_to_a_miss_and_never_raises(store: CacheStore, content: str, fragment: str) -> None:
    """A cache that raises has converted an optimisation into an outage."""
    key = cache_key(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8")
    path = store.path_for(provider="otx", scope=SCOPE_IP, key=key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    lookup = store.get(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert lookup.is_hit is False
    assert fragment in lookup.reason


def test_the_indicator_is_never_a_path_component(store: CacheStore) -> None:
    """On the bulk path the indicator is attacker-authored text. A filename derived from it is a
    traversal waiting to happen; the key is a hex digest and cannot be anything else."""
    hostile = "../../../../etc/passwd"
    key = cache_key(provider="rdap", scope=SCOPE_DOMAIN, indicator=hostile)

    path = store.path_for(provider="rdap", scope=SCOPE_DOMAIN, key=key)

    assert ".." not in path.parts
    assert path.name == f"{key}.json"
    assert store.root in path.parents


def test_a_url_password_does_not_land_in_the_stored_entry(store: CacheStore) -> None:
    """A cache file is the kind of thing that gets attached to a ticket. Matching is on the key,
    which is computed from the raw value, so redacting the stored copy costs nothing."""
    url = "https://example.test/login?apikey=SUPERSECRET"
    store.put(
        provider="virustotal_url",
        scope="url",
        indicator=url,
        payload={"ok": True, "data": {}},
        queried_at=NOW,
        now=NOW,
    )

    lookup = store.get(provider="virustotal_url", scope="url", indicator=url, now=NOW)

    assert lookup.state is CacheState.HIT
    assert lookup.entry is not None
    assert "SUPERSECRET" not in lookup.entry.indicator


def test_a_written_entry_leaves_no_temp_files_behind(store: CacheStore) -> None:
    """Atomic replace, so a concurrent reader never sees half a file."""
    store.put(
        provider="rdap",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {}},
        queried_at=NOW,
        now=NOW,
    )

    written = sorted(p.name for p in store.root.rglob("*") if p.is_file())

    assert len(written) == 1
    assert written[0].endswith(".json")
    assert not written[0].startswith(".")


def test_a_disabled_ruleset_stores_nothing_and_serves_nothing(tmp_path: Path) -> None:
    disabled = CacheStore(tmp_path, config=CacheConfig(enabled=False))

    stored = disabled.put(
        provider="rdap", scope=SCOPE_IP, indicator="8.8.8.8", payload={"ok": True, "data": {}}, queried_at=NOW
    )
    lookup = disabled.get(provider="rdap", scope=SCOPE_IP, indicator="8.8.8.8", now=NOW)

    assert stored is None
    assert lookup.state is CacheState.DISABLED


def test_the_entry_is_frozen_so_nothing_can_restamp_it() -> None:
    """There is no ``touch()`` and no setter, by construction rather than by convention."""
    entry = CacheEntry(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        key="k",
        queried_at="2026-08-09T11:40:00Z",
        stored_at="2026-08-09T11:40:00Z",
        ttl_seconds=3600,
        payload={"ok": True},
    )

    with pytest.raises(ValidationError):
        entry.queried_at = "2026-08-09T12:00:00Z"  # type: ignore[misc]


def test_the_cache_root_is_outside_the_working_tree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A cache under the repo would need a ``.gitignore`` rule to stay uncommitted, and a rule
    is a thing that can be edited away. ``$XDG_CACHE_HOME`` is not."""
    monkeypatch.delenv("TRIPPER_RECON_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))

    assert default_cache_root() == tmp_path / "xdg" / "tripper_recon"


# --------------------------------------------------------------------------------------
# The session: every replay is recorded
# --------------------------------------------------------------------------------------


def test_a_hit_is_recorded_with_its_age_and_a_note_that_says_it_was_not_queried_now(store: CacheStore) -> None:
    """The disclosure block that ``_status_map`` copies onto ``provider_status``. If this is
    absent, a consumer reading ``outcome == "ok"`` cannot tell a lookup from a replay."""
    store.put(
        provider="otx",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {"otx_pulse_count": 3}},
        queried_at=_stamp(600),
        now=_stamp(600),
    )
    session = CacheSession(store, now=NOW)

    session.lookup(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8")
    record = session.record_for(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8")

    assert record is not None
    assert record["hit"] is True
    assert record["queried_at"] == "2026-08-09T11:50:00Z"
    assert record["age"] == "10m"
    assert "NOT queried now" in record["note"]


def test_a_fresh_lookup_is_recorded_as_fresh(store: CacheStore) -> None:
    session = CacheSession(store, now=NOW)

    session.store_payload(
        provider="otx", scope=SCOPE_IP, indicator="8.8.8.8", payload={"ok": True, "data": {}}, queried_at=NOW
    )
    record = session.record_for(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8")

    assert record == {"hit": False, "state": "fresh", "reason": "queried now", "age_seconds": 0.0, "age": "0s"}


def test_a_session_without_a_store_is_inert() -> None:
    """The default for every library caller: no session, no caching, behaviour unchanged."""
    session = CacheSession(None)

    lookup = session.lookup(provider="otx", scope=SCOPE_IP, indicator="8.8.8.8")

    assert session.enabled is False
    assert lookup.state is CacheState.DISABLED


def test_use_cache_installs_and_removes_the_session(store: CacheStore) -> None:
    session = CacheSession(store)

    assert active_cache() is None
    with use_cache(session):
        assert active_cache() is session
    assert active_cache() is None


# --------------------------------------------------------------------------------------
# Freshness: the distinction the coverage ratio structurally cannot make
# --------------------------------------------------------------------------------------


def _status(outcome: str, cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"outcome": outcome, "elapsed_seconds": 0.1}
    if cache is not None:
        entry["cache"] = cache
    return entry


def test_freshness_splits_queried_now_from_replayed() -> None:
    """ "8 of 8 providers answered" is true of a run that queried everything a second ago and of
    a run that replayed everything from last Tuesday. This is the sentence that tells them apart."""
    data = {
        "provider_status": {
            "virustotal": _status("ok", {"hit": False, "state": "fresh"}),
            "otx": _status("ok", {"hit": True, "queried_at": "2026-08-09T11:19:00Z", "age_seconds": 2460.0}),
            "rdap": _status("ok", {"hit": True, "queried_at": "2026-08-08T12:00:00Z", "age_seconds": 86400.0}),
            "abuseipdb": _status("not_configured"),
        }
    }

    summary = summarise_freshness(data)

    assert summary["answered_total"] == 3
    assert summary["answered_now"] == 1
    assert summary["answered_from_cache"] == 2
    assert summary["queried_now"] == ["virustotal"]
    assert summary["oldest_age"] == "1d"
    assert summary["oldest_queried_at"] == "2026-08-08T12:00:00Z"
    assert "1 queried now, 2 from cache (oldest 1d)" in summary["headline"]


def test_freshness_reaches_into_every_scope_the_orchestrators_publish() -> None:
    """Namespaced exactly as ``Coverage`` namespaces them, so the two can never state a ratio in
    different vocabularies."""
    data = {
        "url_provider_status": {"virustotal_url": _status("ok", {"hit": True, "age_seconds": 60.0})},
        "domain_provider_status": {"otx": _status("ok", {"hit": False, "state": "fresh"})},
        "ips": [{"ip": "8.8.8.8", "provider_status": {"rdap": _status("ok", {"hit": True, "age_seconds": 120.0})}}],
    }

    summary = summarise_freshness(data)

    assert summary["answered_now"] == 1
    assert sorted(row["provider"] for row in summary["from_cache"]) == ["8.8.8.8:rdap", "url:virustotal_url"]
    assert summary["queried_now"] == ["domain:otx"]


def test_an_answer_with_no_cache_block_counts_as_queried_now() -> None:
    """The no-session case, and the shape every pre-7.7 payload has."""
    summary = summarise_freshness({"provider_status": {"virustotal": _status("ok")}})

    assert summary["answered_now"] == 1
    assert summary["answered_from_cache"] == 0


def test_the_freshness_warning_says_the_values_were_not_queried_now() -> None:
    """Nothing renders ``data['freshness']`` on the console, so the disclosure travels as a
    warning -- and it has to lead with the count and the age."""
    summary = summarise_freshness(
        {
            "provider_status": {
                "otx": _status("ok", {"hit": True, "queried_at": "2026-08-09T11:19:00Z", "age_seconds": 2460.0})
            }
        }
    )

    warnings = freshness_warnings(summary)

    assert len(warnings) == 1
    assert "NOT queried now" in warnings[0]
    assert "41m" in warnings[0]
    assert "2026-08-09T11:19:00Z" in warnings[0]
    assert "--max-age 0" in warnings[0]


def test_offline_refusals_are_named_in_their_own_warning() -> None:
    summary = summarise_freshness(
        {
            "provider_status": {
                "otx": _status("skipped", {"hit": False, "state": "offline_refused", "reason": "no entry"})
            }
        },
        offline=True,
    )

    warnings = freshness_warnings(summary)

    assert summary["unanswerable_offline"] == [{"provider": "otx", "reason": "no entry"}]
    assert any("could not be answered from cache" in text and "otx" in text for text in warnings)
    assert any("missing coverage, not a clean result" in text for text in warnings)


# --------------------------------------------------------------------------------------
# _call_provider: the one gate the cache lives in
# --------------------------------------------------------------------------------------


class _CountingProvider:
    """A provider that records how many times it was actually invoked."""

    def __init__(self, payload: Dict[str, Any]) -> None:
        self.payload = payload
        self.calls = 0

    async def __call__(self) -> Dict[str, Any]:
        self.calls += 1
        return self.payload


async def test_the_second_identical_call_costs_nothing(store: CacheStore) -> None:
    """The quota relief, stated as the property that produces it: a domain with eight A records
    asks VirusTotal about the same address once, not once per run."""
    provider = _CountingProvider({"ok": True, "data": {"vt_reputation": 7}})
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        first = await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")
        second = await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")

    assert provider.calls == 1
    assert first.data == second.data == {"vt_reputation": 7}
    assert session.hits == 1


async def test_a_different_indicator_is_a_different_question(store: CacheStore) -> None:
    provider = _CountingProvider({"ok": True, "data": {}})
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")
        await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.4.4")

    assert provider.calls == 2


async def test_without_a_session_nothing_is_cached_and_nothing_is_written(tmp_path: Path) -> None:
    """The default. A library caller sees exactly the pre-7.7 behaviour."""
    provider = _CountingProvider({"ok": True, "data": {}})

    await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")
    await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")

    assert provider.calls == 2
    assert not list(tmp_path.iterdir())


async def test_a_call_with_no_indicator_is_never_cached(store: CacheStore) -> None:
    """A key that does not name the thing being asked about would collide across targets."""
    provider = _CountingProvider({"ok": True, "data": {}})
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        await orchestrators._call_provider("virustotal", provider)
        await orchestrators._call_provider("virustotal", provider)

    assert provider.calls == 2


async def test_offline_refuses_rather_than_serving_an_expired_entry(store: CacheStore) -> None:
    """THE ``--offline`` RULE. The expired value is right there and nearly fresh; serving it is
    exactly how a cache becomes a mechanism for laundering staleness."""
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {"vt_reputation": -99}},
        queried_at=_stamp(7200),
        now=_stamp(7200),
    )
    provider = _CountingProvider({"ok": True, "data": {"vt_reputation": 0}})
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        call = await orchestrators._call_provider("virustotal", provider, scope=SCOPE_IP, indicator="8.8.8.8")

    assert provider.calls == 0
    assert call.outcome.value == "skipped"
    assert call.data == {}
    assert call.error["error"] == "offline_no_usable_cache"
    assert call.error["cache_state"] == "stale"
    assert call.error["cached_age"] == "2h"
    assert "-99" not in json.dumps(call.error)


async def test_offline_refuses_a_call_it_could_never_have_cached(store: CacheStore) -> None:
    """Offline is a boundary, not a preference. A call with nothing to key on has nothing it
    could have been served from, so it is refused rather than sent."""
    provider = _CountingProvider({"ok": True, "data": {}})
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        call = await orchestrators._call_provider("virustotal", provider)

    assert provider.calls == 0
    assert call.outcome.value == "skipped"


async def test_a_cached_call_closes_a_coroutine_it_did_not_await(store: CacheStore) -> None:
    """The eager call form still works, and a hit does not leave a coroutine dangling.

    ``tests/test_http.py`` drives ``_call_provider`` with a coroutine rather than a factory, so
    both forms have to survive. An un-awaited coroutine raises ``RuntimeWarning`` at collection
    time -- a failure under ``-W error`` -- which is why the cache lane closes it explicitly.
    """
    store.put(
        provider="virustotal",
        scope=SCOPE_IP,
        indicator="8.8.8.8",
        payload={"ok": True, "data": {"vt_reputation": 7}},
        queried_at=NOW,
        now=NOW,
    )
    provider = _CountingProvider({"ok": True, "data": {}})
    session = CacheSession(store, now=NOW)
    coroutine = provider()

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with use_cache(session):
            call = await orchestrators._call_provider("virustotal", coroutine, scope=SCOPE_IP, indicator="8.8.8.8")
        del coroutine
        gc.collect()

    assert provider.calls == 0
    assert call.data == {"vt_reputation": 7}


# --------------------------------------------------------------------------------------
# End to end: --offline makes exactly zero network calls
# --------------------------------------------------------------------------------------
#
# These register NO respx routes on purpose. `tests/conftest.no_real_network` refuses anything
# nothing else claimed, so a single request from the offline path fails the test rather than
# quietly leaving the box.


def _seed_ip_providers(store: CacheStore, ip: str, *, age_seconds: float) -> None:
    """Warm the cache as a previous run would have left it."""
    payloads = {
        "virustotal": {"vt_last_analysis_stats": {"malicious": 0, "harmless": 70}},
        "ipinfo": {"ip": ip, "asn": 15169, "country": "US"},
        "internetdb": {"ports": [443], "source": "internetdb"},
        "abuseipdb": {"abuseipdb_reports": 0, "abuseipdb_confidence_score": 0},
        "otx": {"otx_pulse_count": 0},
        "rdap": {"rdap_handle": "NET-8-8-8-0-1"},
        "abusech": {"urlhaus_listed": False},
    }
    for provider, data in payloads.items():
        store.put(
            provider=provider,
            scope=SCOPE_IP,
            indicator=ip,
            payload={"ok": True, "data": data},
            queried_at=_stamp(age_seconds),
            now=_stamp(age_seconds),
        )


async def test_offline_with_a_cold_cache_contacts_nobody_and_says_so(store: CacheStore) -> None:
    """No routes are registered. If this test ever reaches a socket it fails, which is the point."""
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    assert result.ok is False
    assert result.coverage is not None
    assert result.coverage.answered_count == 0
    assert result.data["freshness"]["offline"] is True
    assert result.data["freshness"]["answered_total"] == 0
    assert any("--offline" in text for text in result.warnings)
    assert any("intelligence blackout" in text for text in result.errors)


async def test_offline_with_a_warm_cache_answers_and_labels_every_answer_a_replay(store: CacheStore) -> None:
    """The feature, end to end: a full report, no egress, and nothing claiming to be current."""
    _seed_ip_providers(store, "8.8.8.8", age_seconds=1800)
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    freshness = result.data["freshness"]
    assert result.ok is True
    assert freshness["answered_now"] == 0
    assert freshness["answered_from_cache"] == 7
    assert freshness["oldest_age"] == "30m"
    assert "none was queried now" in freshness["headline"]
    assert result.data["provider_status"]["virustotal"]["cache"]["hit"] is True
    assert result.data["provider_status"]["virustotal"]["cache"]["queried_at"] == "2026-08-09T11:30:00Z"
    assert result.data["virustotal"]["vt_last_analysis_stats"]["harmless"] == 70


async def test_the_one_provider_offline_could_not_reach_is_named_not_hidden(store: CacheStore) -> None:
    """Cloudflare's ASN lookup is a second wave keyed on the ASN, and nothing seeded it. It has
    to appear as a stated gap -- in coverage, in the freshness block, and in the warnings."""
    _seed_ip_providers(store, "8.8.8.8", age_seconds=60)
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    assert result.coverage is not None
    assert "cloudflare_asn" in result.coverage.skipped
    assert result.data["freshness"]["unanswerable_offline"] == [
        {"provider": "cloudflare_asn", "reason": "nothing is filed under this key"}
    ]
    assert any("cloudflare_asn" in text for text in result.warnings)


async def test_max_age_turns_a_usable_entry_into_a_stated_gap_offline(store: CacheStore) -> None:
    """An analyst who demanded freshness gets a gap rather than a value that fails the demand."""
    _seed_ip_providers(store, "8.8.8.8", age_seconds=1800)
    session = CacheSession(store, offline=True, max_age_seconds=300, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    assert result.ok is False
    assert result.data["freshness"]["answered_total"] == 0
    reasons = {row["reason"] for row in result.data["freshness"]["unanswerable_offline"]}
    assert any("--max-age" in reason for reason in reasons)


async def test_offline_does_not_resolve_the_domain(monkeypatch: pytest.MonkeyPatch, store: CacheStore) -> None:
    """The system resolver is the tool's one non-provider egress. ``--offline`` is worth nothing
    if it still tells a nameserver what the operator is looking at."""
    from tripper_recon.utils import dns as dns_module

    async def _explode(_domain: str) -> List[str]:
        raise AssertionError("--offline resolved a name")

    monkeypatch.setattr(dns_module, "resolve_domain", _explode)
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        result = await investigate_domain("evil.example")

    assert any("--offline" in text and "not resolved" in text for text in result.warnings)
    assert result.data["addresses"]["resolved"] == 0
    assert result.data["collection"]["passive_only"] is True


async def test_a_replayed_resolution_is_announced_and_is_not_an_active_step(
    monkeypatch: pytest.MonkeyPatch, store: CacheStore
) -> None:
    """A cached A record is a historical claim about a mapping that fast-flux exists to
    invalidate, so the report says when it was resolved and that nothing was resolved now."""
    from tripper_recon.utils import dns as dns_module

    async def _explode(_domain: str) -> List[str]:
        raise AssertionError("a cached resolution was re-resolved")

    monkeypatch.setattr(dns_module, "resolve_domain", _explode)
    store.put(
        provider=orchestrators.DNS_PROVIDER,
        scope=SCOPE_DOMAIN,
        indicator="evil.example",
        payload={"ok": True, "data": {"addresses": ["10.0.0.5"]}},
        queried_at=_stamp(120),
        now=_stamp(120),
    )
    session = CacheSession(store, offline=True, now=NOW)

    with use_cache(session):
        result = await investigate_domain("evil.example")

    assert any("replayed from cache" in text and "2m ago" in text for text in result.warnings)
    assert result.data["collection"]["passive_only"] is True
    # The address came back and was still refused by the non-public guard, which is the correct
    # interaction: a cached resolution is evidence, not an exemption.
    assert result.data["skipped_ips"] == [{"ip": "10.0.0.5", "source": "active", "reason": "private"}]


async def test_a_failed_resolution_is_not_cached_as_an_empty_answer(
    monkeypatch: pytest.MonkeyPatch, store: CacheStore
) -> None:
    """``resolve_domain`` returns ``[]`` for NXDOMAIN and for a resolver timeout alike. Filing
    that as a successful observation would let one flaky lookup teach the cache that a domain
    has no addresses."""
    from tripper_recon.utils import dns as dns_module

    async def _empty(_domain: str) -> List[str]:
        return []

    monkeypatch.setattr(dns_module, "resolve_domain", _empty)
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        await orchestrators._resolve_addresses("evil.example")

    lookup = store.get(provider=orchestrators.DNS_PROVIDER, scope=SCOPE_DOMAIN, indicator="evil.example", now=NOW)
    assert lookup.state is CacheState.MISS


async def test_the_asn_metadata_lookup_is_shared_across_addresses(store: CacheStore) -> None:
    """Where most of the quota relief on a multi-address domain actually comes from: Cloudflare's
    ASN record is a property of the ASN, so eight addresses in one network ask once."""
    session = CacheSession(store, now=NOW)
    provider = _CountingProvider({"ok": True, "data": {"asn": 15169, "name": "GOOGLE"}})

    with use_cache(session):
        await orchestrators._call_provider("cloudflare_asn", provider, scope=SCOPE_ASN, indicator="15169")
        await orchestrators._call_provider("cloudflare_asn", provider, scope=SCOPE_ASN, indicator="15169")

    assert provider.calls == 1


# --------------------------------------------------------------------------------------
# The case directory
# --------------------------------------------------------------------------------------


def _result() -> Dict[str, Any]:
    return {
        "ok": True,
        "data": {"ip": "8.8.8.8", "run": {"run_id": "20260809T120000Z-abcd1234"}},
        "warnings": [],
        "errors": [],
    }


def test_a_case_round_trips(tmp_path: Path) -> None:
    paths = write_case(
        tmp_path,
        result=_result(),
        indicator="8.8.8.8",
        scope=SCOPE_IP,
        run_id="20260809T120000Z-abcd1234",
        report="# report\n",
        cache_summary={"hits": 3},
        now=NOW,
    )

    record = load_case(paths.directory)

    assert record["schema_version"] == CASE_SCHEMA
    assert record["case_id"] == case_id_for(SCOPE_IP, "8.8.8.8")
    assert record["run_id"] == "20260809T120000Z-abcd1234"
    assert record["written_at"] == "2026-08-09T12:00:00Z"
    assert record["cache"] == {"hits": 3}
    assert record["result"]["data"]["ip"] == "8.8.8.8"
    assert paths.report is not None and paths.report.read_text(encoding="utf-8") == "# report\n"


def test_the_case_id_is_deterministic_and_the_run_keeps_two_runs_apart(tmp_path: Path) -> None:
    """A downstream system dedupes on the case id; the run id is what stops the second run from
    overwriting the first one's evidence."""
    first = write_case(tmp_path, result=_result(), indicator="8.8.8.8", scope=SCOPE_IP, run_id="run-a", now=NOW)
    second = write_case(tmp_path, result=_result(), indicator="8.8.8.8", scope=SCOPE_IP, run_id="run-b", now=NOW)

    assert first.directory.parent == second.directory.parent
    assert first.directory != second.directory
    assert first.case_json.is_file() and second.case_json.is_file()


def test_the_indicator_is_never_a_directory_name(tmp_path: Path) -> None:
    """Same rule as the cache path, and it matters more here: on the bulk path this string came
    out of an attacker's email."""
    paths = write_case(
        tmp_path, result=_result(), indicator="../../etc/passwd", scope=SCOPE_DOMAIN, run_id="r", now=NOW
    )

    assert ".." not in paths.directory.parts
    assert tmp_path.resolve() in paths.directory.resolve().parents


def test_a_url_password_does_not_reach_the_case_record(tmp_path: Path) -> None:
    """A case directory is what gets attached to a ticket."""
    paths = write_case(
        tmp_path,
        result=_result(),
        indicator="https://example.test/x?token=SUPERSECRET",
        scope="url",
        run_id="r",
        now=NOW,
    )

    assert "SUPERSECRET" not in paths.case_json.read_text(encoding="utf-8")


def test_evidence_envelopes_are_written_and_counted(tmp_path: Path) -> None:
    class _Envelope:
        host = "www.virustotal.com"

        def to_json(self) -> str:
            return '{"schema_version": "tripper-recon.evidence/1"}'

    paths = write_case(
        tmp_path,
        result=_result(),
        indicator="8.8.8.8",
        scope=SCOPE_IP,
        run_id="r",
        evidence=[_Envelope(), _Envelope()],
        evidence_complete=False,
        evidence_dropped=4,
        now=NOW,
    )

    record = load_case(paths.case_json)

    assert paths.evidence_written == 2
    assert record["evidence"] == {"captured": 2, "complete": False, "dropped": 4, "directory": "evidence"}
    assert sorted(p.name for p in (paths.evidence_dir or tmp_path).iterdir()) == [
        "0001-www.virustotal.com.json",
        "0002-www.virustotal.com.json",
    ]


def test_the_case_says_whether_its_location_is_git_ignored(tmp_path: Path) -> None:
    """A disclosure, not a control. ``.gitignore`` ignores ``outputs/`` as a directory and git
    does not descend into one, so a case written there cannot be committed by accident -- and
    the honest answer for a ``--case-dir`` pointed elsewhere is "no"."""
    covered = write_case(tmp_path / "outputs", result=_result(), indicator="8.8.8.8", scope=SCOPE_IP, now=NOW)
    exposed = write_case(tmp_path / "elsewhere", result=_result(), indicator="8.8.8.8", scope=SCOPE_IP, now=NOW)

    assert load_case(covered.directory)["git_ignored_location"] is True
    assert load_case(exposed.directory)["git_ignored_location"] is False


def test_the_default_case_root_is_under_the_ignored_outputs_directory() -> None:
    assert default_case_root() == Path.cwd() / "outputs" / "cases"


def test_a_missing_case_is_an_error_not_an_empty_report(tmp_path: Path) -> None:
    with pytest.raises(CacheError, match="no case record"):
        load_case(tmp_path / "nope")


def test_a_future_case_schema_is_refused(tmp_path: Path) -> None:
    """Partially understanding a record whose field meanings have changed is worse than
    refusing it: the report would quote them with confidence."""
    path = tmp_path / "case.json"
    path.write_text(json.dumps({"schema_version": "tripper-recon.case/9"}), encoding="utf-8")

    with pytest.raises(CacheError, match="schema"):
        load_case(path)


async def test_an_online_run_with_a_warm_cache_still_contacts_nobody_and_says_why(store: CacheStore) -> None:
    """The quota relief in its ordinary form: not ``--offline``, just a second run within the
    lifetime. No routes are registered, so any request fails the test.

    The warning is the half that makes it defensible. Without it the console shows a full report
    with eight of eight answered and nothing anywhere saying the answers are half an hour old.
    """
    _seed_ip_providers(store, "8.8.8.8", age_seconds=1800)
    store.put(
        provider="cloudflare_asn",
        scope=SCOPE_ASN,
        indicator="15169",
        payload={"ok": True, "data": {"asn": 15169, "name": "GOOGLE"}},
        queried_at=_stamp(1800),
        now=_stamp(1800),
    )
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    assert result.ok is True
    assert session.hits == 8
    assert result.coverage is not None and result.coverage.is_complete is True
    assert result.data["freshness"]["answered_from_cache"] == 8
    # The disclosure leads the warning list, ahead of the coverage sentences: a reader who sees
    # only the first line has to be shown that "8 of 8 answered" is a claim about the past.
    assert "NOT queried now" in result.warnings[0]
    assert "30m" in result.warnings[0]
    # The ASN metadata is filed at ASN scope, so its record still has to be found and reported.
    assert result.data["provider_status"]["cloudflare_asn"]["cache"]["hit"] is True


async def test_a_replayed_answer_is_indistinguishable_in_the_data_and_labelled_in_the_status(
    store: CacheStore,
) -> None:
    """Both halves of the contract, asserted together.

    The payload is replayed byte-for-byte -- a cached answer is the same EVIDENCE as a fresh one,
    and downgrading it would be its own dishonesty. What changes is the record beside it, which
    is where the difference belongs.
    """
    _seed_ip_providers(store, "8.8.8.8", age_seconds=60)
    session = CacheSession(store, now=NOW)

    with use_cache(session):
        result = await investigate_ip("8.8.8.8")

    assert result.data["otx"] == {"otx_pulse_count": 0}
    status = result.data["provider_status"]["otx"]
    assert status["outcome"] == "ok"
    assert status["cache"]["hit"] is True
    assert status["cache"]["age"] == "1m"
    assert status["cache"]["expires_at"] == "2026-08-09T12:59:00Z"
