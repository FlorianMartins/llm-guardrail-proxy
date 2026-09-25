"""Application factory and entry point."""

from __future__ import annotations

import re
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from . import __version__
from .audit import configure_logging
from .config import Settings, get_settings
from .providers import Provider, build_provider
from .router import router
from .schemas import openai_error

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def create_app(
    settings: Settings | None = None,
    provider: Provider | None = None,
) -> FastAPI:
    """``provider`` lets tests inject an adapter wired to an in-process fake backend."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_file)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.backend = provider or build_provider(settings)
        yield
        await app.state.backend.aclose()

    app = FastAPI(
        title="LLM Guardrail Proxy",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.settings = settings

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        # Accept the caller's id only if it is harmless (it ends up in logs).
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        type_ = "authentication_error" if exc.status_code == 401 else "invalid_request_error"
        return JSONResponse(openai_error(str(exc.detail), type_), status_code=exc.status_code)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(router)
    return app


def run() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_config=None)


if __name__ == "__main__":
    run()
