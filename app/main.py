"""HTTP 层：接收原始 .eml 字节，逐条返回验签结论。无状态，不存邮件。"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .dkim import verify_signature
from .keystore import KeyStore
from .parser import MessageParseError, parse_message

DEFAULT_KEY_STORE = "keys/keys.json"


def create_app(
    *,
    keystore: KeyStore | None = None,
    key_store_path: str | None = None,
    max_message_bytes: int | None = None,
    max_headers: int | None = None,
    max_signatures: int | None = None,
) -> FastAPI:
    if keystore is None:
        keystore = KeyStore(
            key_store_path or os.environ.get("DKIM_KEY_STORE", DEFAULT_KEY_STORE)
        )
    if max_message_bytes is None:
        max_message_bytes = int(os.environ.get("DKIM_MAX_MESSAGE_BYTES", 10 * 1024 * 1024))
    if max_headers is None:
        max_headers = int(os.environ.get("DKIM_MAX_HEADERS", 500))
    if max_signatures is None:
        max_signatures = int(os.environ.get("DKIM_MAX_SIGNATURES", 20))

    app = FastAPI(title="DKIM Mail Verifier")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/verify")
    async def verify(request: Request):
        data = await request.body()
        if len(data) > max_message_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "detail": f"message too large: {len(data)} bytes "
                    f"(limit {max_message_bytes})"
                },
            )
        try:
            msg = parse_message(data, max_headers=max_headers)
        except MessageParseError as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})

        sig_indices = [
            i for i, h in enumerate(msg.headers) if h.name.lower() == "dkim-signature"
        ]
        if not sig_indices:
            return {
                "overall": "none",
                "reason": "no DKIM-Signature header found",
                "signatures": [],
            }

        omitted = max(0, len(sig_indices) - max_signatures)
        results = [
            verify_signature(msg, i, keystore).as_dict()
            for i in sig_indices[:max_signatures]
        ]
        response = {
            "overall": "pass"
            if any(r["result"] == "pass" for r in results)
            else "fail",
            "signatures": results,
        }
        if omitted:
            response["note"] = (
                f"{omitted} DKIM-Signature header(s) skipped "
                f"(limit {max_signatures})"
            )
        return response

    return app


app = create_app()
