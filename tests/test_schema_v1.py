from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

try:
    import pydantic  # noqa: F401
except ModuleNotFoundError as exc:  # pragma: no cover - environment guard
    raise unittest.SkipTest("Project runtime dependencies are not installed") from exc

from tripper_recon.api.server import api_domain, api_ip
from tripper_recon.cli import _cmd_domain, _cmd_investigate, _cmd_ip
from tripper_recon.orchestrators import investigate_domain
from tripper_recon.provider_registry import Capability, Mode, ProviderSelectionError, select_providers
from tripper_recon.schema_v1 import InvestigationResultV1, ip_result_to_schema_v1
from tripper_recon.types.models import ApiKeys, InvestigationResult


REQUIRED_KEYS = {
    "schema_version",
    "target_type",
    "input",
    "normalized_target",
    "mode",
    "profile",
    "execution_status",
    "verdict",
    "score",
    "confidence",
    "findings",
    "relationships",
    "provider_status",
    "evidence",
    "cache",
    "errors",
    "warnings",
}


def legacy_ip_result() -> InvestigationResult:
    return InvestigationResult(
        ok=True,
        data={
            "ipinfo": {"asn": 15169, "country": "US"},
            "virustotal": {"reputation": 0},
        },
        warnings=[],
        errors=[],
    )


def legacy_domain_result() -> InvestigationResult:
    return InvestigationResult(
        ok=True,
        data={
            "domain": "example.com",
            "domain_intel": {
                "virustotal": {
                    "vt_dns_records": [
                        {"type": "A", "value": "1.1.1.1"},
                    ],
                },
                "otx": {"otx_pulse_count": 0},
            },
            "ips": [
                {"ip": "1.1.1.1"},
            ],
        },
        warnings=[],
        errors=[],
    )


class FakeAsyncClient:
    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


class SchemaV1Tests(unittest.IsolatedAsyncioTestCase):
    def test_ip_adapter_returns_required_schema_without_top_level_ok(self) -> None:
        result = ip_result_to_schema_v1(target="8.8.8.8", result=legacy_ip_result())
        payload = result.model_dump()

        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["target_type"], "ip")
        self.assertEqual(payload["execution_status"], "completed")
        self.assertEqual(payload["mode"], "passive")
        self.assertEqual(payload["profile"], "best_effort")

    def test_provider_registry_skips_default_disallowed_provider(self) -> None:
        selection = select_providers(target_type="ip", mode=Mode.PASSIVE)

        self.assertIn("ipinfo", selection.executable)
        skipped = {status.provider: status for status in selection.skipped}
        self.assertEqual(skipped["local_dns"].status, "skipped")
        self.assertIn(Capability.ANALYST_RESOLVER.value, skipped["local_dns"].reason or "")

    def test_provider_registry_fails_explicit_disallowed_provider(self) -> None:
        with self.assertRaises(ProviderSelectionError):
            select_providers(
                target_type="ip",
                mode=Mode.PASSIVE,
                requested_providers=["local_dns"],
            )

    def test_provider_registry_skips_default_domain_dns_provider(self) -> None:
        selection = select_providers(target_type="domain", mode=Mode.PASSIVE)

        self.assertIn("virustotal", selection.executable)
        skipped = {status.provider: status for status in selection.skipped}
        self.assertEqual(skipped["local_dns"].status, "skipped")

    def test_resolver_passive_allows_local_dns_but_blocks_direct_active(self) -> None:
        selection = select_providers(target_type="domain", mode=Mode.RESOLVER_PASSIVE)

        self.assertIn("local_dns", selection.executable)
        with self.assertRaises(ProviderSelectionError):
            select_providers(
                target_type="domain",
                mode=Mode.RESOLVER_PASSIVE,
                requested_providers=["direct_http"],
            )

    async def test_cli_single_ip_json_uses_schema_v1(self) -> None:
        stdout = io.StringIO()
        with patch("tripper_recon.cli.investigate_ip", new=AsyncMock(return_value=legacy_ip_result())):
            with contextlib.redirect_stdout(stdout):
                code = await _cmd_ip("8.8.8.8", output="json")

        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["normalized_target"], "8.8.8.8")
        skipped = {status["provider"]: status for status in payload["provider_status"] if status["status"] == "skipped"}
        self.assertIn("local_dns", skipped)

    async def test_cli_explicit_disallowed_provider_fails_before_investigation(self) -> None:
        stdout = io.StringIO()
        mock_investigate = AsyncMock(return_value=legacy_ip_result())
        with patch("tripper_recon.cli.investigate_ip", new=mock_investigate):
            with contextlib.redirect_stdout(stdout):
                code = await _cmd_ip("8.8.8.8", output="json", providers=["local_dns"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["execution_status"], "failed")
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["provider_status"][0]["provider"], "local_dns")
        mock_investigate.assert_not_awaited()

    async def test_api_ip_uses_schema_v1(self) -> None:
        with patch("tripper_recon.service.investigate_ip", new=AsyncMock(return_value=legacy_ip_result())):
            payload = await api_ip("8.8.8.8")

        InvestigationResultV1.model_validate(payload)
        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["target_type"], "ip")

    async def test_cli_domain_json_uses_schema_v1_with_passive_relationship(self) -> None:
        stdout = io.StringIO()
        with patch("tripper_recon.cli.investigate_domain", new=AsyncMock(return_value=legacy_domain_result())):
            with contextlib.redirect_stdout(stdout):
                code = await _cmd_domain("example.com", output="json")

        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["target_type"], "domain")
        self.assertEqual(payload["mode"], "passive")
        self.assertEqual(payload["relationships"][0]["target"], "1.1.1.1")
        skipped = {status["provider"]: status for status in payload["provider_status"] if status["status"] == "skipped"}
        self.assertIn("local_dns", skipped)

    async def test_cli_investigate_json_outputs_jsonl_without_stderr_summary(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("8.8.8.8\nexample.com\n")
            path = Path(handle.name)

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with patch("tripper_recon.service.investigate_ip", new=AsyncMock(return_value=legacy_ip_result())):
                with patch("tripper_recon.service.investigate_domain", new=AsyncMock(return_value=legacy_domain_result())):
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = await _cmd_investigate(str(path), output="json")
        finally:
            path.unlink(missing_ok=True)

        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual([line["target_type"] for line in lines], ["ip", "domain"])
        for line in lines:
            self.assertTrue(REQUIRED_KEYS.issubset(line.keys()))
            self.assertNotIn("ok", line)

    async def test_cli_investigate_json_emits_failed_schema_row_for_unimplemented_target(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = await _cmd_investigate("https://example.com/path", output="json")

        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(payload["target_type"], "url")
        self.assertEqual(payload["execution_status"], "failed")
        self.assertNotIn("ok", payload)

    async def test_api_domain_uses_schema_v1(self) -> None:
        with patch("tripper_recon.service.investigate_domain", new=AsyncMock(return_value=legacy_domain_result())):
            payload = await api_domain("example.com")

        InvestigationResultV1.model_validate(payload)
        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["target_type"], "domain")

    async def test_api_accepts_machine_parameters_and_uses_shared_ip_service(self) -> None:
        with patch("tripper_recon.service.investigate_ip", new=AsyncMock(return_value=legacy_ip_result())) as mock_investigate:
            payload = await api_ip(
                "8.8.8.8",
                mode="resolver-passive",
                profile="best_effort",
                providers="ipinfo,virustotal",
                include_raw=True,
                require_profile_complete=False,
                cache=False,
            )

        self.assertEqual(payload["mode"], "resolver-passive")
        self.assertEqual(payload["profile"], "best_effort")
        self.assertEqual([status["provider"] for status in payload["provider_status"]], ["ipinfo", "virustotal"])
        mock_investigate.assert_awaited_once_with("8.8.8.8")

    async def test_api_provider_validation_returns_schema_failure_without_secret_leak(self) -> None:
        with patch("tripper_recon.service.investigate_domain", new=AsyncMock(return_value=legacy_domain_result())) as mock_investigate:
            payload = await api_domain("example.com", providers="direct_http")

        self.assertEqual(payload["execution_status"], "failed")
        self.assertEqual(payload["provider_status"][0]["provider"], "direct_http")
        self.assertNotIn("ok", payload)
        self.assertNotIn("apikey", json.dumps(payload).lower())
        mock_investigate.assert_not_awaited()

    async def test_passive_domain_investigation_does_not_call_dns(self) -> None:
        provider_missing = {"ok": False, "error": "missing_api_key"}
        with patch("tripper_recon.orchestrators.create_client", return_value=FakeAsyncClient()):
            with patch(
                "tripper_recon.orchestrators._env_keys",
                return_value=ApiKeys(vt_api_key="vt", otx_api_key="otx"),
            ), patch(
                "tripper_recon.orchestrators.vt_domain_summary",
                new=AsyncMock(
                    return_value={
                        "ok": True,
                        "data": {"vt_dns_records": [{"type": "A", "value": "1.1.1.1"}]},
                    }
                ),
            ), patch(
                "tripper_recon.orchestrators.otx_domain_pulses",
                new=AsyncMock(return_value={"ok": True, "data": {}}),
            ), patch(
                "tripper_recon.orchestrators.vt_ip_summary",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.shodan_host",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.ipinfo_ip",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.abuseipdb_check",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.otx_ip_pulses",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.utils.dns.resolve_domain",
                new=AsyncMock(side_effect=AssertionError("DNS called")),
            ):
                result = await investigate_domain("example.com", mode="passive")

        self.assertTrue(result.ok)
        self.assertEqual(result.data["ips"][0]["ip"], "1.1.1.1")

    async def test_resolver_passive_domain_investigation_calls_dns_and_ptr(self) -> None:
        provider_missing = {"ok": False, "error": "missing_api_key"}
        with patch("tripper_recon.orchestrators.create_client", return_value=FakeAsyncClient()):
            with patch(
                "tripper_recon.orchestrators._env_keys",
                return_value=ApiKeys(vt_api_key="vt", otx_api_key="otx"),
            ), patch(
                "tripper_recon.orchestrators.vt_domain_summary",
                new=AsyncMock(return_value={"ok": True, "data": {"vt_dns_records": []}}),
            ), patch(
                "tripper_recon.orchestrators.otx_domain_pulses",
                new=AsyncMock(return_value={"ok": True, "data": {}}),
            ), patch(
                "tripper_recon.orchestrators.vt_ip_summary",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.shodan_host",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.ipinfo_ip",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.abuseipdb_check",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.orchestrators.otx_ip_pulses",
                new=AsyncMock(return_value=provider_missing),
            ), patch(
                "tripper_recon.utils.dns.resolve_domain",
                new=AsyncMock(return_value=["1.1.1.1"]),
            ) as resolve_mock, patch(
                "tripper_recon.utils.dns.reverse_ptr",
                new=AsyncMock(return_value="one.one.one.one"),
            ) as ptr_mock:
                result = await investigate_domain("example.com", mode="resolver-passive")

        self.assertTrue(result.ok)
        self.assertEqual(result.data["ips"][0]["ip"], "1.1.1.1")
        self.assertEqual(result.data["ips"][0]["ptr"], "one.one.one.one")
        self.assertEqual(result.data["ips"][0]["relationship_source"], "analyst_resolver")
        resolve_mock.assert_awaited_once_with("example.com")
        ptr_mock.assert_awaited_once_with("1.1.1.1")


if __name__ == "__main__":
    unittest.main()
