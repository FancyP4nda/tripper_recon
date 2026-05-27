from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest.mock import AsyncMock, patch

try:
    import pydantic  # noqa: F401
except ModuleNotFoundError as exc:  # pragma: no cover - environment guard
    raise unittest.SkipTest("Project runtime dependencies are not installed") from exc

from tripper_recon.api.server import api_ip
from tripper_recon.cli import _cmd_ip
from tripper_recon.schema_v1 import InvestigationResultV1, ip_result_to_schema_v1
from tripper_recon.types.models import InvestigationResult


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

    async def test_api_ip_uses_schema_v1(self) -> None:
        with patch("tripper_recon.api.server.investigate_ip", new=AsyncMock(return_value=legacy_ip_result())):
            payload = await api_ip("8.8.8.8")

        InvestigationResultV1.model_validate(payload)
        self.assertTrue(REQUIRED_KEYS.issubset(payload.keys()))
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["target_type"], "ip")


if __name__ == "__main__":
    unittest.main()
