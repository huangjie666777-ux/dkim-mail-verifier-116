#!/usr/bin/env python3
"""Generate a demo RSA key pair and a signed email for the curl demo.

Usage:
    .venv/bin/python scripts/make_demo.py

Produces:
    keys.json            - public key store for the verifier
    demo_private.pem     - private key (keep secret; not used by the verifier)
    valid.eml            - a valid DKIM-signed message
    tampered.eml         - the same message with the body modified
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dkim_verifier.canonicalization import canonicalize_body, canonicalize_header  # noqa: E402
from dkim_verifier.parser import Header  # noqa: E402


def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (ROOT / "demo_private.pem").write_bytes(private_pem)
    (ROOT / "keys.json").write_text(
        json.dumps(
            {"example.com": {"selector1": public_pem.decode("ascii")}},
            indent=2,
        )
        + "\n"
    )

    headers = [
        ("From", "Sender <sender@example.com>"),
        ("To", "Recipient <rcpt@example.com>"),
        ("Subject", "DKIM demo message"),
        ("Date", "Thu, 2 Oct 2026 12:00:00 +0000"),
    ]
    body = (
        b"Hello,\r\n"
        b"\r\n"
        b"This is a DKIM-signed demo message.\r\n"
        b"It uses simple/simple canonicalization.\r\n"
        b"\r\n"
        b"Regards,\r\n"
        b"The Demo\r\n"
    )

    h_fields = [name for name, _ in headers]
    canonical_body = canonicalize_body(body, "simple")
    bh = base64.b64encode(hashlib.sha256(canonical_body).digest()).decode()

    h_list = ":".join(h_fields)
    sig_value = (
        f"v=1; a=rsa-sha256; d=example.com; s=selector1; "
        f"c=simple/simple; h={h_list}; bh={bh}; b="
    )

    # Select h= headers bottom-up, mirroring the verifier.
    available = list(headers)
    selected: list[Header] = []
    for field in h_fields:
        for i in range(len(available) - 1, -1, -1):
            if available[i][0].lower() == field.lower():
                name, value = available.pop(i)
                selected.append(
                    Header(name.encode(), name.encode() + b":" + value.encode() + b"\r\n")
                )
                break

    sig_header = Header(
        b"DKIM-Signature",
        b"DKIM-Signature:" + sig_value.encode() + b"\r\n",
    )
    hash_input = b"".join(
        canonicalize_header(h, "simple", is_signature=False) for h in selected
    )
    hash_input += canonicalize_header(sig_header, "simple", is_signature=True)[:-2]
    signature = private_key.sign(hash_input, padding.PKCS1v15(), hashes.SHA256())

    sig_value_full = sig_value + base64.b64encode(signature).decode()
    raw_headers = b"".join(
        name.encode() + b":" + value.encode() + b"\r\n" for name, value in headers
    )
    valid = (
        b"DKIM-Signature:" + sig_value_full.encode() + b"\r\n" + raw_headers + b"\r\n" + body
    )
    (ROOT / "valid.eml").write_bytes(valid)

    tampered = valid.replace(b"This is a DKIM-signed demo message.", b"This is a TAMPERED message.", 1)
    (ROOT / "tampered.eml").write_bytes(tampered)

    print("wrote keys.json, demo_private.pem, valid.eml, tampered.eml")


if __name__ == "__main__":
    main()
