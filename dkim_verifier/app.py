"""FastAPI HTTP layer for the DKIM verifier.

The service accepts raw ``.eml`` bytes via ``POST /verify`` and returns
per-signature verification results. Messages are never stored; each
request is processed independently.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .keys import KeyStore, KeyStoreError
from .verifier import verify_message

DEFAULT_MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MiB
DEFAULT_MAX_HEADERS = 100
DEFAULT_MAX_SIGNATURES = 10


def create_app(key_store: KeyStore | None = None) -> FastAPI:
    app = FastAPI(title="DKIM Mail Verifier", version="1.0.0")

    keys_path = os.environ.get("DKIM_KEYS_PATH", "keys.json")
    max_message_size = int(
        os.environ.get("DKIM_MAX_MESSAGE_SIZE", DEFAULT_MAX_MESSAGE_SIZE)
    )
    max_headers = int(os.environ.get("DKIM_MAX_HEADERS", DEFAULT_MAX_HEADERS))
    max_signatures = int(os.environ.get("DKIM_MAX_SIGNATURES", DEFAULT_MAX_SIGNATURES))

    if key_store is None:
        try:
            key_store = KeyStore.load(keys_path)
        except (OSError, KeyStoreError) as exc:
            raise RuntimeError(
                f"failed to load key store from {keys_path!r}: {exc}"
            ) from exc

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/verify")
    async def verify(request: Request) -> JSONResponse:
        raw = await request.body()
        if len(raw) > max_message_size:
            return JSONResponse(
                status_code=413,
                content={
                    "status": "error",
                    "reason": (
                        f"message too large: {len(raw)} bytes > {max_message_size} limit"
                    ),
                    "signatures": [],
                },
            )
        result = verify_message(
            raw,
            key_store,
            max_headers=max_headers,
            max_signatures=max_signatures,
        )
        return JSONResponse(status_code=200, content=result)

    return app
