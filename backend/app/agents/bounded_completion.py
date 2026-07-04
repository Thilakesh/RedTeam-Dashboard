"""Async wrapper around OpenRouter's OpenAI-compatible API with JSON mode enforced.

Uses OPENROUTER_API_KEY from settings. Raises BoundedCompletionError on any failure
so callers can treat it as optional (scan stage is optional=True).
"""
from __future__ import annotations

import json
from typing import NamedTuple

import httpx

from app.core.config import get_settings

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


class BoundedCompletionError(RuntimeError):
    """Raised when the OpenRouter call fails for any reason."""


class CompletionResult(NamedTuple):
    content: dict           # parsed JSON from model response
    prompt_tokens: int
    completion_tokens: int


async def bounded_completion(
    *,
    system: str,
    user: str,
    model: str = "openai/gpt-oss-20b:free",
    api_key: str | None = None,
    max_input_chars: int = 40_000,
    timeout: float = 120.0,
) -> CompletionResult:
    """Call OpenRouter with JSON mode and a hard input character cap.

    If len(user) > max_input_chars, the user string is truncated and a
    '[truncated: input exceeded limit]' marker is appended so the model
    knows the list is incomplete.

    Returns CompletionResult on success.
    Raises BoundedCompletionError on HTTP error, timeout, or empty API key.
    """
    api_key = api_key or get_settings().openrouter_api_key
    if not api_key:
        raise BoundedCompletionError(
            "OPENROUTER_API_KEY is not set — cannot call risk prioritizer"
        )

    if len(user) > max_input_chars:
        user = user[:max_input_chars] + "\n[truncated: input exceeded limit]"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                OPENROUTER_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise BoundedCompletionError(
            f"OpenRouter HTTP error: {exc.response.status_code}"
        ) from exc
    except httpx.TimeoutException as exc:
        raise BoundedCompletionError("OpenRouter request timed out") from exc
    except ValueError as exc:
        raise BoundedCompletionError(
            f"Failed to parse OpenRouter response body: {exc}"
        ) from exc
    try:
        choice = data["choices"][0]
        finish_reason = choice.get("finish_reason", "unknown")
        raw = choice["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise BoundedCompletionError(
            f"Unexpected OpenRouter response structure: {exc}"
        ) from exc

    if raw is None:
        raise BoundedCompletionError(
            f"OpenRouter returned null content (finish_reason={finish_reason!r}, "
            f"model={model!r}) — free model may be rate-limited or unavailable"
        )

    try:
        content = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BoundedCompletionError(
            f"OpenRouter returned invalid JSON (finish_reason={finish_reason!r}): {exc}"
        ) from exc

    usage = data.get("usage") or {}
    return CompletionResult(
        content=content,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
    )
