"""Async wrapper around OpenRouter's OpenAI-compatible API with JSON mode enforced.

Uses OPENROUTER_API_KEY from settings. Raises BoundedCompletionError on any failure
so callers can treat it as optional (scan stage is optional=True).
"""
from __future__ import annotations

import json
import logging
from typing import NamedTuple

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free-tier / flaky-provider responses (empty content, or a malformed body caused
# by OpenRouter's SSE keep-alive comments leaking into a non-streamed response)
# are worth retrying — they're transient, not a real failure. HTTP errors,
# timeouts, and a missing API key are NOT retried: those aren't flaky-provider
# symptoms and retrying them just wastes the stage's time budget.
MAX_TRANSIENT_RETRIES = 2


class BoundedCompletionError(RuntimeError):
    """Raised when the OpenRouter call fails for any reason."""


class ResponseTruncatedError(BoundedCompletionError):
    """Raised when the model hit max_tokens mid-JSON (finish_reason='length').

    This is deterministic given the same input + max_tokens — retrying with an
    unchanged token budget just reproduces the same truncation. Callers should
    scale max_tokens to the input size instead of retrying this.
    """


class CompletionResult(NamedTuple):
    content: dict           # parsed JSON from model response
    prompt_tokens: int
    completion_tokens: int


def _strip_sse_noise(raw: str) -> str:
    """Strip stray SSE comment/keep-alive lines (e.g. ": OPENROUTER PROCESSING")
    that OpenRouter occasionally leaks into a non-streamed response body."""
    lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.lstrip().startswith(":")]
    return "\n".join(lines).strip()


async def _attempt(
    *,
    system: str,
    user: str,
    model: str,
    api_key: str,
    max_tokens: int,
    timeout: float,
) -> CompletionResult:
    """One HTTP call + parse. Raises BoundedCompletionError on any failure;
    the retry loop in bounded_completion() decides which failures to retry."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": max_tokens,
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
            body_text = resp.text
    except httpx.HTTPStatusError as exc:
        raise BoundedCompletionError(
            f"OpenRouter HTTP error: {exc.response.status_code}"
        ) from exc
    except httpx.TimeoutException as exc:
        raise BoundedCompletionError("OpenRouter request timed out") from exc

    try:
        data = json.loads(body_text)
    except json.JSONDecodeError:
        cleaned = _strip_sse_noise(body_text)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
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

    if not raw or not raw.strip():
        raise BoundedCompletionError(
            f"OpenRouter returned empty content (finish_reason={finish_reason!r}, "
            f"model={model!r}) — free model may be rate-limited or unavailable"
        )

    try:
        content = json.loads(raw)
    except json.JSONDecodeError:
        cleaned = _strip_sse_noise(raw)
        try:
            content = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            if finish_reason == "length":
                raise ResponseTruncatedError(
                    f"OpenRouter truncated the response mid-JSON (finish_reason='length', "
                    f"max_tokens={max_tokens}) — the input was too large for the token "
                    f"budget: {exc}"
                ) from exc
            raise BoundedCompletionError(
                f"OpenRouter returned invalid JSON (finish_reason={finish_reason!r}): {exc}"
            ) from exc

    usage = data.get("usage") or {}
    return CompletionResult(
        content=content,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
    )


async def bounded_completion(
    *,
    system: str,
    user: str,
    model: str = "deepseek/deepseek-v4-flash",
    api_key: str | None = None,
    max_input_chars: int = 40_000,
    max_tokens: int = 8000,
    timeout: float = 120.0,
) -> CompletionResult:
    """Call OpenRouter with JSON mode and a hard input character cap.

    If len(user) > max_input_chars, the user string is truncated and a
    '[truncated: input exceeded limit]' marker is appended so the model
    knows the list is incomplete.

    Empty-content and malformed-body responses (both symptomatic of flaky
    free-tier providers) are retried up to MAX_TRANSIENT_RETRIES times. HTTP
    errors, timeouts, a missing API key, and a max_tokens truncation
    (ResponseTruncatedError — deterministic, not flaky) fail immediately,
    unretried.

    Returns CompletionResult on success.
    Raises BoundedCompletionError on final failure.
    """
    api_key = api_key or get_settings().openrouter_api_key
    if not api_key:
        raise BoundedCompletionError(
            "OPENROUTER_API_KEY is not set — cannot call risk prioritizer"
        )

    if len(user) > max_input_chars:
        user = user[:max_input_chars] + "\n[truncated: input exceeded limit]"

    last_exc: BoundedCompletionError | None = None
    for attempt in range(MAX_TRANSIENT_RETRIES + 1):
        try:
            return await _attempt(
                system=system,
                user=user,
                model=model,
                api_key=api_key,
                max_tokens=max_tokens,
                timeout=timeout,
            )
        except ResponseTruncatedError:
            # Deterministic given the same input + max_tokens — retrying reproduces
            # the identical truncation, so fail immediately instead of burning the
            # retry budget on a guaranteed repeat.
            raise
        except BoundedCompletionError as exc:
            msg = str(exc)
            transient = "empty content" in msg or "invalid JSON" in msg or "Failed to parse" in msg
            if not transient or attempt == MAX_TRANSIENT_RETRIES:
                raise
            last_exc = exc
            logger.warning(
                "bounded_completion: transient failure (attempt %d/%d), retrying: %s",
                attempt + 1,
                MAX_TRANSIENT_RETRIES + 1,
                msg,
            )

    # Unreachable — the loop always returns or raises — but keeps type checkers happy.
    raise last_exc or BoundedCompletionError("bounded_completion: exhausted retries")
