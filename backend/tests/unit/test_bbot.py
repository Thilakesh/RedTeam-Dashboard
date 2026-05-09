import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext

BBOT_OUTPUT = b"""\
{"type": "DNS_NAME", "data": "www.example.com"}
{"type": "DNS_NAME", "data": "api.example.com"}
{"type": "DNS_NAME", "data": "evil.com"}
{"type": "IP_ADDRESS", "data": "1.2.3.4"}
not-valid-json-line
{"type": "DNS_NAME", "data": "www.example.com"}
{"type": "UNKNOWN_TYPE", "data": "ignored.example.com"}
"""


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


def _make_proc(stdout: bytes = BBOT_OUTPUT) -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    proc.kill = MagicMock()
    return proc


@pytest.mark.asyncio
async def test_happy_path_returns_subdomains_and_ips(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)
    keys = {r.canonical_key for r in records}
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "1.2.3.4" in keys


@pytest.mark.asyncio
async def test_domain_filter_excludes_cross_domain(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)
    keys = {r.canonical_key for r in records}
    assert "evil.com" not in keys
    assert "ignored.example.com" not in keys


@pytest.mark.asyncio
async def test_deduplication(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)
    subdomain_keys = [r.canonical_key for r in records if r.type == "subdomain"]
    assert subdomain_keys.count("www.example.com") == 1


@pytest.mark.asyncio
async def test_malformed_json_lines_skipped(ctx):
    proc = _make_proc()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1800
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)
    assert len(records) > 0


@pytest.mark.asyncio
async def test_timeout_returns_empty_and_kills_process(ctx):
    proc = MagicMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    proc.kill = MagicMock()
    with patch("asyncio.create_subprocess_exec", return_value=proc), \
         patch("app.pipeline.adapters.bbot.get_settings") as mock_s:
        mock_s.return_value.bbot_timeout = 1
        from app.pipeline.adapters.bbot import BBOTStage
        records = await BBOTStage().execute(ctx)
    proc.kill.assert_called_once()
    assert records == []
