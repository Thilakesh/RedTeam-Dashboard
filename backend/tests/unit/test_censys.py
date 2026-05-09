import sys
import types
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.pipeline.stage import StageContext


@pytest.fixture
def ctx():
    return StageContext(scan_id=uuid4(), target_id=uuid4(), domain="example.com")


def _make_censys_mock(search_return=None, search_side_effect=None):
    """Build a fake censys.search module with a CensysHosts class."""
    mock_hosts_instance = MagicMock()
    if search_side_effect is not None:
        mock_hosts_instance.search.side_effect = search_side_effect
    else:
        mock_hosts_instance.search.return_value = iter(search_return or [])

    mock_hosts_cls = MagicMock(return_value=mock_hosts_instance)

    censys_search_mod = types.ModuleType("censys.search")
    censys_search_mod.CensysHosts = mock_hosts_cls

    censys_mod = types.ModuleType("censys")

    return censys_mod, censys_search_mod, mock_hosts_cls, mock_hosts_instance


@pytest.mark.asyncio
async def test_no_credentials_returns_empty(ctx):
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s:
        mock_s.return_value.censys_api_id = ""
        mock_s.return_value.censys_api_secret = ""
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    assert records == []


@pytest.mark.asyncio
async def test_cache_hit_skips_api_call(ctx):
    cached = [{"type": "subdomain", "canonical_key": "www.example.com",
               "payload": {"source": "censys"}, "confidence": 90}]
    censys_mod, censys_search_mod, mock_hosts_cls, _ = _make_censys_mock()
    mock_set = AsyncMock()
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=cached)), \
         patch("app.pipeline.adapters.censys.cache_set", mock_set), \
         patch.dict(sys.modules, {"censys": censys_mod, "censys.search": censys_search_mod}):
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    mock_hosts_cls.assert_not_called()
    mock_set.assert_not_called()
    assert len(records) == 1
    assert records[0].canonical_key == "www.example.com"


@pytest.mark.asyncio
async def test_happy_path_domain_filter(ctx):
    fake_hosts = [{"ip": "1.2.3.4",
                   "parsed": {"names": ["www.example.com", "api.example.com", "other.evil.com"]}}]
    censys_mod, censys_search_mod, mock_hosts_cls, _ = _make_censys_mock(search_return=fake_hosts)
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=None)), \
         patch("app.pipeline.adapters.censys.cache_set", new=AsyncMock()), \
         patch.dict(sys.modules, {"censys": censys_mod, "censys.search": censys_search_mod}):
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    keys = {r.canonical_key for r in records}
    assert "1.2.3.4" in keys
    assert "www.example.com" in keys
    assert "api.example.com" in keys
    assert "other.evil.com" not in keys


@pytest.mark.asyncio
async def test_api_error_returns_empty(ctx):
    censys_mod, censys_search_mod, _, mock_hosts_instance = _make_censys_mock(
        search_side_effect=Exception("401 Unauthorized")
    )
    with patch("app.pipeline.adapters.censys.get_settings") as mock_s, \
         patch("app.pipeline.adapters.censys.cache_get", new=AsyncMock(return_value=None)), \
         patch.dict(sys.modules, {"censys": censys_mod, "censys.search": censys_search_mod}):
        mock_s.return_value.censys_api_id = "id"
        mock_s.return_value.censys_api_secret = "secret"
        mock_s.return_value.redis_url = "redis://localhost:6379/0"
        from app.pipeline.adapters.censys import CensysStage
        records = await CensysStage().execute(ctx)
    assert records == []
