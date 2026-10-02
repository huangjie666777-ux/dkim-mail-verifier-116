import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.keystore import KeyStore
from app.main import create_app
from scripts.dkim_signer import sign_message

DOMAIN = "example.com"
SELECTOR = "s1"

BASE_MESSAGE = (
    b"Received: from mail.example.com by mx.example.org\r\n"
    b"Received: from localhost by mail.example.com\r\n"
    b"From: Alice <alice@example.com>\r\n"
    b"To: Bob <bob@example.org>\r\n"
    b"Subject: DKIM test\r\n"
    b"\twith folded part\r\n"
    b"Date: Thu, 02 Oct 2026 10:00:00 +0000\r\n"
    b"\r\n"
    b"Hello Bob,\r\n"
    b"this is a test body.\r\n"
)

H_NAMES = ["received", "received", "from", "to", "subject", "date"]


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


@pytest.fixture()
def keystore(public_pem):
    return KeyStore.from_dict({DOMAIN: {SELECTOR: public_pem}})


@pytest.fixture()
def client(keystore):
    from fastapi.testclient import TestClient

    return TestClient(create_app(keystore=keystore))


@pytest.fixture()
def sign(private_key):
    def _sign(message: bytes, **kwargs) -> bytes:
        kwargs.setdefault("private_key", private_key)
        kwargs.setdefault("domain", DOMAIN)
        kwargs.setdefault("selector", SELECTOR)
        kwargs.setdefault("h_names", H_NAMES)
        return sign_message(message, **kwargs)

    return _sign
