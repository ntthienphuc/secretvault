"""FastAPI ingress for the Python API and optional same-origin web client."""

from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from vaultserver.server import VaultHTTPServer
from .handler import CloudHandler
from .store import CloudStore


def create_app(*, serve_web=True):
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    persistent = Path(os.getenv("SV_PERSISTENT_DIR", ".data/persistent"))
    runtime = Path(os.getenv("SV_RUNTIME_DIR", ".data/runtime"))
    if os.getenv("SV_BUCKET_ID"):
        from .bucket import BucketStore

        store = BucketStore(runtime, persistent, os.environ["SV_BUCKET_ID"])
    else:
        if os.getenv("RENDER"):
            raise RuntimeError(
                "Configure private bucket persistence before starting the online service"
            )
        store = CloudStore(runtime, persistent)
    web = Path(os.getenv("SV_WEB_DIR", "web"))
    server = VaultHTTPServer(("127.0.0.1", 0), store, web, behind_proxy=True)
    server.RequestHandlerClass = CloudHandler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    allowed = [
        o.strip().rstrip("/")
        for o in os.getenv(
            "SV_ALLOWED_ORIGINS", "http://127.0.0.1:8787,http://localhost:8787"
        ).split(",")
        if o.strip()
    ]

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            timeout=90, limits=httpx.Limits(max_connections=20)
        ) as client:
            app.state.http = client
            yield
        server.shutdown()
        server.server_close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = store
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,
        max_age=600,
    )

    @app.middleware("http")
    async def ingress(request: Request, call_next):
        if not request.url.path.startswith("/api/") and request.method not in (
            "GET",
            "HEAD",
        ):
            # Static assets and the service status endpoint are read-only.
            return JSONResponse({"error": "Method not allowed"}, status_code=405)
        if request.url.path.startswith("/api/"):
            source = request.headers.get("origin")
            if source and source not in allowed:
                return JSONResponse({"error": "Origin bị từ chối"}, status_code=403)
            # Each encrypted file chunk fits in a bounded API request.
            try:
                size = int(request.headers.get("content-length", "0"))
            except ValueError:
                size = 99999999
            if size > 2 * 1048576:
                return JSONResponse({"error": "Request vượt giới hạn"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "DELETE"])
    async def api_proxy(request: Request, path: str):
        content = bytearray()
        async for part in request.stream():
            content.extend(part)
            if len(content) > 2 * 1048576:
                return JSONResponse({"error": "Request vượt giới hạn"}, status_code=413)
        headers = {
            "X-Forwarded-Proto": "https",
            "X-SV-Remote-IP": request.headers.get(
                "x-forwarded-for", request.client.host if request.client else "unknown"
            )
            .split(",")[-1]
            .strip(),
        }
        for name in ("Authorization", "Content-Type"):
            if request.headers.get(name):
                headers[name] = request.headers[name]
        try:
            result = await request.app.state.http.request(
                request.method,
                origin
                + request.url.path
                + ("?" + request.url.query if request.url.query else ""),
                headers=headers,
                content=bytes(content),
            )
        except httpx.HTTPError:
            return JSONResponse(
                {"error": "Máy chủ đang khởi động. Thử lại sau ít phút."},
                status_code=503,
            )
        return Response(
            result.content,
            status_code=result.status_code,
            media_type=result.headers.get("content-type"),
            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
        )

    if serve_web:
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        @app.get("/admin")
        @app.get("/setup")
        async def spa():
            return FileResponse(web / "index.html")

        app.mount("/", StaticFiles(directory=str(web), html=True), name="web")
    else:

        @app.get("/")
        async def service_status():
            return {
                "app": "SecretVault",
                "status": "ready",
                "web": os.getenv(
                    "SV_FRONTEND_URL", "https://secretvault-online.vercel.app"
                ),
            }

    return app


if __name__ == "__main__":
    import uvicorn

    on_render = bool(os.getenv("RENDER"))
    uvicorn.run(
        create_app(serve_web=not on_render or os.getenv("SV_LOCAL_WEB") == "1"),
        host=os.getenv("HOST", "0.0.0.0" if on_render else "127.0.0.1"),
        port=int(os.getenv("PORT", "8787")),
    )
