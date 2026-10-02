"""演示/测试用签名工具：复用验证端的规范化与选头逻辑，保证与验签一致。

仅用于生成演示邮件和测试夹具，不属于验签后端本身。
"""
from __future__ import annotations

import base64
import hashlib
import textwrap

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.canonicalize import canonicalize_body, canonicalize_header
from app.dkim import select_headers
from app.parser import parse_message


def sign_message(
    message: bytes,
    *,
    private_key,
    domain: str,
    selector: str,
    h_names: list[str],
    header_c: str = "simple",
    body_c: str = "simple",
) -> bytes:
    """对 CRLF 邮件签名，返回顶部插入 DKIM-Signature 后的完整邮件。"""
    msg = parse_message(message)
    bh = base64.b64encode(
        hashlib.sha256(canonicalize_body(msg.body, body_c)).digest()
    ).decode("ascii")
    dkim_value = (
        f"v=1; a=rsa-sha256; c={header_c}/{body_c}; d={domain}; s={selector}; "
        f"h={':'.join(h_names)}; bh={bh}; b="
    )
    selected = select_headers(msg, -1, [n.lower() for n in h_names])
    hash_input = b"".join(
        canonicalize_header(f.name, f.raw, header_c) for f in selected
    )
    hash_input += canonicalize_header(
        "DKIM-Signature",
        b"DKIM-Signature: " + dkim_value.encode("ascii") + b"\r\n",
        header_c,
    )
    signature = private_key.sign(hash_input, padding.PKCS1v15(), hashes.SHA256())
    b64 = base64.b64encode(signature).decode("ascii")
    # 只在 b 值内部折行（续行以空格开头），避免折进标签名
    folded_b = "\r\n ".join(textwrap.wrap(b64, 72))
    dkim_header = "DKIM-Signature: " + dkim_value + "\r\n " + folded_b + "\r\n"
    return dkim_header.encode("ascii") + message
