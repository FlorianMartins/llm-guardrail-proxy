from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from guardrail_proxy.config import Settings
from guardrail_proxy.main import create_app


class FakeLLM:
    """In-process OpenAI-compatible backend. Records what it received, so tests
    can assert on what actually left the proxy (the whole point of masking)."""

    def __init__(self) -> None:
        self.answer = "Hello! How can I help?"
        self.received: list[dict[str, Any]] = []
        self.status = 200
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            raise httpx.ConnectError("boom", request=request)
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"object": "list", "data": [{"id": "llama3"}]})
        body = json.loads(request.content)
        self.received.append(body)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"message": "upstream says no"}})
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": self.answer},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
            },
        )


@pytest.fixture
def llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture
def make_client(llm: FakeLLM):
    def _make(**overrides: Any) -> TestClient:
        settings = Settings(backend_url="http://fake/v1", _env_file=None, **overrides)
        app = create_app(settings, transport=httpx.MockTransport(llm.handler))
        return TestClient(app)

    return _make


@pytest.fixture
def client(make_client):
    with make_client() as c:
        yield c


def chat(content: str, **extra: Any) -> dict[str, Any]:
    return {"model": "llama3", "messages": [{"role": "user", "content": content}], **extra}
