"""FastAPI application factory for the web dashboard and API.

``create_app`` wires a :class:`GuardianPipeline` into a FastAPI application:
REST + WebSocket endpoints under ``/api`` and the no-build web dashboard
served from ``backend/dashboard/web``. A background :class:`PipelineDriver`
(optionally with a custom tick) keeps the pipeline moving and streams
changes to connected clients.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.changes import ChangeLog
from backend.api.driver import PipelineDriver, TickFn
from backend.api.ratelimit import RateLimitMiddleware
from backend.api.routes import api_router, ws_router
from backend.api.security import Authenticator
from backend.api.state import RuntimeState
from backend.core.config import AppConfig
from backend.pipeline import GuardianPipeline

WEB_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "web"


def create_app(
    pipeline: GuardianPipeline,
    config: AppConfig,
    *,
    start_driver: bool = True,
    tick: TickFn | None = None,
) -> FastAPI:
    """Build the GuardianOS-AI API + dashboard application."""
    changes = ChangeLog()
    authenticator = Authenticator(config.auth)
    driver = (
        PipelineDriver(
            pipeline,
            changes,
            refresh_seconds=config.server.refresh_seconds,
            tick=tick,
        )
        if start_driver
        else None
    )
    state = RuntimeState(
        pipeline=pipeline,
        changes=changes,
        authenticator=authenticator,
        driver=driver,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if driver is not None:
            driver.start()
        yield
        if driver is not None:
            driver.stop()

    app = FastAPI(title="GuardianOS-AI API", version="0.1.0", lifespan=lifespan)
    app.state.guardian = state

    rpm = config.server.rate_limit_rpm
    if rpm > 0:
        app.add_middleware(RateLimitMiddleware, requests_per_minute=rpm)

    app.include_router(api_router)
    app.include_router(ws_router)

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    # SPA catch-all: serve the React app for client-side routes (deep links).
    # Anything under /api or /static that did not match a route is a 404.
    @app.get("/{full_path:path}", include_in_schema=False, response_model=None)
    async def spa(full_path: str) -> FileResponse | JSONResponse:
        if full_path.startswith(("api/", "static/")):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        return FileResponse(WEB_DIR / "index.html")

    return app
