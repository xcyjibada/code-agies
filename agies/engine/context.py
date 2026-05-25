"""Context compression and Anthropic prompt cache annotation.

Two functions:

1. ``compress_context()`` — triggered when an LLM call exceeds the context
   window.  Drops middle messages, keeps system + first user + last 1/3.
2. ``apply_cache_annotations()`` — marks system and last few user/tool
   messages with Anthropic's ``cache_control`` for prompt caching.

Reference: Xint ``agent.py`` lines 301-314 (ContextWindowExceeded recovery).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context compression — recover from context window overflow
# ---------------------------------------------------------------------------


def compress_context(msgs: list[dict]) -> list[dict]:
    """Drop middle messages when the context window is exceeded.

    Strategy — keep:
    1. System message + first user message (indispensable context)
    2. A *[context compressed]* notice so the LLM knows some history is gone
    3. The most recent 1/3 of messages (latest tool results + last assistant)

    Raises ``ValueError`` if there are too few messages to compress.
    """
    if len(msgs) < 3:
        raise ValueError(
            f"Not enough messages to compress ({len(msgs)})."
        )

    prefix = msgs[:2]  # system + first user
    prefix.append({"role": "user", "content": "[context compressed]"})

    # Keep the most recent 1/3 of messages
    split = 2 * len(msgs) // 3
    suffix = msgs[split:]

    # Ensure the suffix starts with an assistant message (tool results
    # without the preceding assistant call are meaningless)
    while suffix and suffix[0].get("role") != "assistant":
        suffix.pop(0)

    if not suffix:
        raise ValueError("No assistant messages in suffix after compression.")

    compressed = prefix + suffix
    logger.info(
        "Context compressed: %d messages → %d messages (dropped %d).",
        len(msgs),
        len(compressed),
        len(msgs) - len(compressed),
    )
    return compressed


# ---------------------------------------------------------------------------
# Anthropic prompt cache annotations
# ---------------------------------------------------------------------------


def apply_cache_annotations(msgs: list[dict]) -> list[dict]:
    """Add ``cache_control`` to cacheable messages.

    Applied to:
    - The system message (high cache hit rate for stable instructions)
    - The last 2 user/tool messages that follow an assistant message
      (the LLM re-reads these on retry loops).

    Mutates messages in place.  This is fine since the caller owns the list.
    """
    # System message
    for msg in msgs:
        if msg.get("role") == "system":
            _annotate_system(msg)
            break

    # Last 2 user/tool messages preceded by an assistant
    seen = 0
    prev_role: str | None = None
    for msg in reversed(msgs):
        role = msg.get("role", "")
        if role in ("user", "tool") and prev_role == "assistant":
            _annotate_content(msg)
            seen += 1
            if seen >= 2:
                break
        prev_role = role

    return msgs


def _annotate_system(msg: dict) -> None:
    """Convert system string to content-block format with cache_control."""
    content = msg.get("content", "")
    if isinstance(content, str):
        msg["content"] = [
            {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}},
        ]
    elif isinstance(content, list) and content:
        content[0]["cache_control"] = {"type": "ephemeral"}


def _annotate_content(msg: dict) -> None:
    """Add cache_control to a user/tool message's content."""
    content = msg.get("content", "")
    if isinstance(content, str):
        msg["content"] = [
            {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}},
        ]
    elif isinstance(content, list) and content:
        content[0]["cache_control"] = {"type": "ephemeral"}
