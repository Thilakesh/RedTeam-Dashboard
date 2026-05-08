"""Unit tests for bounded_completion — all OpenRouter calls are mocked."""
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def api_key_env():
    """Inject a fake API key and clear the lru_cache so Settings re-reads env."""
    os.environ["OPENROUTER_API_KEY"] = "test-key-abc"
    get_settings.cache_clear()
    yield
    os.environ.pop("OPENROUTER_API_KEY", None)
    get_settings.cache_clear()


def _mock_client(status: int = 200, body: dict | None = None):
    """Build a mock httpx.AsyncClient that returns the given status and body."""
    if body is None:
        body = {
            "choices": [{"message": {"content": json.dumps({"findings": []})}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
    mock_resp = MagicMock()
    if status >= 400:
        import httpx
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status}",
            request=MagicMock(),
            response=MagicMock(status_code=status),
        )
    else:
        mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value=body)

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(return_value=mock_resp)
    return client


@pytest.mark.asyncio
async def test_happy_path_returns_completion_result():
    from app.agents.bounded_completion import bounded_completion, CompletionResult

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client()):
        result = await bounded_completion(system="sys", user="user")

    assert isinstance(result, CompletionResult)
    assert result.content == {"findings": []}
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 50


@pytest.mark.asyncio
async def test_http_429_raises_bounded_completion_error():
    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client(status=429)):
        with pytest.raises(BoundedCompletionError, match=r"HTTP error: 429"):
            await bounded_completion(system="sys", user="user")


@pytest.mark.asyncio
async def test_http_500_raises_bounded_completion_error():
    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=_mock_client(status=500)):
        with pytest.raises(BoundedCompletionError, match=r"HTTP error: 500"):
            await bounded_completion(system="sys", user="user")


@pytest.mark.asyncio
async def test_input_truncated_when_over_limit():
    """Payload sent to OpenRouter must be <= max_input_chars; truncation marker appended."""
    from app.agents.bounded_completion import bounded_completion

    captured: dict = {}

    async def fake_post(url, json=None, headers=None):
        captured["payload"] = json
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "choices": [{"message": {"content": "{\"findings\":[]}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        })
        return mock_resp

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.post = AsyncMock(side_effect=fake_post)

    long_user = "x" * 50_000
    with patch("app.agents.bounded_completion.httpx.AsyncClient", return_value=client):
        await bounded_completion(system="sys", user=long_user, max_input_chars=40_000)

    sent_user = captured["payload"]["messages"][1]["content"]
    TRUNCATION_MARKER = "\n[truncated: input exceeded limit]"
    assert len(sent_user) == 40_000 + len(TRUNCATION_MARKER)
    assert "[truncated" in sent_user


@pytest.mark.asyncio
async def test_missing_api_key_raises():
    os.environ.pop("OPENROUTER_API_KEY", None)
    get_settings.cache_clear()

    from app.agents.bounded_completion import bounded_completion, BoundedCompletionError

    with pytest.raises(BoundedCompletionError, match="OPENROUTER_API_KEY"):
        await bounded_completion(system="sys", user="user")
