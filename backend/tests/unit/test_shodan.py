import sys
import types
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


def _make_shodan_mock(domain_return=None, domain_side_effect=None):
    """Build a fake shodan module with a Shodan class."""
    mock_api_instance = MagicMock()
    if domain_side_effect is not None:
        mock_api_instance.dns.domain_info.side_effect = domain_side_effect
    else:
        mock_api_instance.dns.domain_info.return_value = domain_return or {}

    mock_shodan_cls = MagicMock(return_value=mock_api_instance)

    shodan_mod = types.ModuleType("shodan")
    shodan_mod.Shodan = mock_shodan_cls

    return shodan_mod, mock_shodan_cls, mock_api_instance


@pytest.mark.asyncio
async def test_no_api_key_returns_empty(ctx):
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s:
        mock_s.return_value.shodan_api_key = ""
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    assert records == []


@pytest.mark.asyncio
async def test_cache_hit_skips_api_call(ctx):
    cached = [{"type": "subdomain", "canonical_key": "www.example.com",
               "payload": {"source": "shodan"}, "confidence": 85}]
    shodan_mod, mock_shodan_cls, _ = _make_shodan_mock()
    mock_set = AsyncMock()
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=cached)), \
         patch("app.pipeline.adapters.shodan.cache_set", mock_set), \
         patch.dict(sys.modules, {"shodan": shodan_mod}):
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    mock_shodan_cls.assert_not_called()
    mock_set.assert_not_called()
    assert len(records) == 1


@pytest.mark.asyncio
async def test_happy_path_constructs_fqdns(ctx):
    fake_result = {"subdomains": ["www", "api", "mail"],
                   "data": [{"type": "A", "value": "1.2.3.4"}, {"type": "MX", "value": "5.6.7.8"}]}
    shodan_mod, _, _ = _make_shodan_mock(domain_return=fake_result)
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.shodan.cache_set", new=AsyncMock()), \
         patch.dict(sys.modules, {"shodan": shodan_mod}):
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    keys = {r.canonical_key for r in records}
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "mail.example.com" in keys
    assert "1.2.3.4" in keys
    assert "5.6.7.8" not in keys


@pytest.mark.asyncio
async def test_api_error_returns_empty(ctx):
    shodan_mod, _, _ = _make_shodan_mock(domain_side_effect=Exception("APIError"))
    with patch("app.pipeline.adapters.shodan.get_settings") as mock_s, \
         patch("app.pipeline.adapters.shodan.cache_get", new=AsyncMock(return_value=None)), \
         patch.dict(sys.modules, {"shodan": shodan_mod}):
        mock_s.return_value.shodan_api_key = "key"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.shodan import ShodanStage
        records = await ShodanStage().execute(ctx)
    assert records == []
