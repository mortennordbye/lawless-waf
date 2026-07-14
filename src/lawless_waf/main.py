"""FastAPI application: WAF tuning context service + web UI."""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .api import activity, analysis, azure, config, datasets, exclusions, geoip
from .ratelimit import limiter
from .settings import get_settings

log = logging.getLogger("lawless_waf")


def create_app() -> FastAPI:
    settings = get_settings()  # validate config at startup; fail fast

    # Nothing is downloading at startup, so any leftover download lock is stale (a previous run
    # killed mid-download). Clear them so a wedged hour doesn't refuse every future download.
    from .cache import DatasetCache

    if removed := DatasetCache(settings.data_dir).clear_stale_locks():
        log.info("cleared %d stale download lock(s)", removed)

    app = FastAPI(
        title="lawless-waf",
        version="0.1.0",
        summary="On-demand Azure WAF log analysis + exclusion context for Claude Code.",
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # There is no app-level auth by design (see SECURITY.md), so a Host allowlist is what stops
    # DNS rebinding: a page the operator visits can rebind its own hostname to 127.0.0.1 and issue
    # *simple* requests to this API from the browser. CORS hides the response but does not stop the
    # request from executing — a rebound DELETE /api/datasets would still run. The browser sends the
    # attacker's hostname in Host, so rejecting anything but the local names blocks it.
    # "api" is the Host the Vite dev proxy sends (VITE_API_PROXY=http://api:8000, changeOrigin).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "api"])

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT"],
            allow_headers=["Content-Type"],
        )

    @app.exception_handler(Exception)
    async def _generic_error(request: Request, exc: Exception) -> JSONResponse:
        # Full detail to server logs only; generic message to the client.
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    # All JSON endpoints live under /api so the SPA can own the rest of the path space.
    api = APIRouter(prefix="/api")

    @api.get("/healthz", tags=["meta"])
    def healthz() -> dict:  # the one explicitly public route
        return {"status": "ok", "offline": settings.offline}

    api.include_router(datasets.router)
    api.include_router(activity.router)
    api.include_router(analysis.router)
    api.include_router(exclusions.router)
    api.include_router(config.router)
    api.include_router(azure.router)
    api.include_router(geoip.router)
    app.include_router(api)
    return app


app = create_app()
