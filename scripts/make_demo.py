"""生成演示材料：RSA 密钥对、keys/keys.json、demo/valid.eml、demo/tampered.eml。

用法：.venv/bin/python scripts/make_demo.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.dkim_signer import sign_message

DOMAIN = "example.com"
SELECTOR = "s1"

MESSAGE = (
    b"Received: from mail.example.com by mx.example.org\r\n"
    b"Received: from localhost by mail.example.com\r\n"
    b"From: Alice <alice@example.com>\r\n"
    b"To: Bob <bob@example.org>\r\n"
    b"Subject: DKIM demo\r\n"
    b"\twith a folded subject line\r\n"
    b"Date: Thu, 02 Oct 2026 10:00:00 +0000\r\n"
    b"Message-ID: <demo-1@example.com>\r\n"
    b"\r\n"
    b"Hello Bob,\r\n"
    b"this is a DKIM verification demo.\r\n"
    b"\r\n"
    b"-- Alice\r\n"
)


def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    keys_dir = ROOT / "keys"
    keys_dir.mkdir(exist_ok=True)
    (keys_dir / "demo_private.pem").write_bytes(priv_pem)  # 仅演示用，已被 .gitignore 排除
    (keys_dir / "keys.json").write_text(
        json.dumps({DOMAIN: {SELECTOR: pub_pem.decode("ascii")}}, indent=2) + "\n"
    )

    signed = sign_message(
        MESSAGE,
        private_key=private_key,
        domain=DOMAIN,
        selector=SELECTOR,
        h_names=["received", "received", "from", "to", "subject", "date", "message-id"],
        header_c="relaxed",
        body_c="simple",
    )

    demo_dir = ROOT / "demo"
    demo_dir.mkdir(exist_ok=True)
    (demo_dir / "valid.eml").write_bytes(signed)
    tampered = signed.replace(
        b"this is a DKIM verification demo.", b"this is a TAMPERED demo body."
    )
    assert tampered != signed
    (demo_dir / "tampered.eml").write_bytes(tampered)

    print(f"keys/keys.json        (公钥库: {DOMAIN} / {SELECTOR})")
    print("keys/demo_private.pem (演示私钥，勿用于生产)")
    print("demo/valid.eml        (有效签名)")
    print("demo/tampered.eml     (正文被篡改)")


if __name__ == "__main__":
    main()
