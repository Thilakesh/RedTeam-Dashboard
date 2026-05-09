import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_deep_scan_enqueues_to_heavy_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services import queue as queue_module
        await queue_module.enqueue_scan("scan-abc", profile="deep")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-abc", _queue_name="heavy")


@pytest.mark.asyncio
async def test_standard_scan_enqueues_to_default_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services import queue as queue_module
        await queue_module.enqueue_scan("scan-def", profile="standard")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-def", _queue_name="default")


@pytest.mark.asyncio
async def test_quick_scan_enqueues_to_default_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services import queue as queue_module
        await queue_module.enqueue_scan("scan-ghi", profile="quick")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-ghi", _queue_name="default")


@pytest.mark.asyncio
async def test_default_profile_enqueues_to_default_queue():
    mock_pool = AsyncMock()
    with patch("app.services.queue.create_pool", new=AsyncMock(return_value=mock_pool)):
        from app.services import queue as queue_module
        await queue_module.enqueue_scan("scan-jkl")
    mock_pool.enqueue_job.assert_called_once_with("run_scan", "scan-jkl", _queue_name="default")
