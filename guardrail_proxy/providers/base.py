"""The contract every backend adapter fulfils.

The proxy speaks the OpenAI chat-completions dialect on both sides of the
guardrails: guards inspect OpenAI-shaped messages, and clients receive
OpenAI-shaped answers. An adapter only translates at the edge, so adding a
provider never touches detection or policy code.
"""

from __future__ import annotations

from typing import Any, Protocol

Result = tuple[int, dict[str, Any]]  # (HTTP status, OpenAI-shaped JSON body)


class BackendError(Exception):
    """The backend could not be reached or answered garbage."""


class Provider(Protocol):
    name: str

    async def chat_completions(self, payload: dict[str, Any]) -> Result: ...

    async def models(self) -> Result: ...

    async def aclose(self) -> None: ...
