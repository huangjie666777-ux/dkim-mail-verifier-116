"""密码学验签原语：RSA PKCS#1 v1.5 + SHA-256。"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256


def verify_rsa_sha256(
    public_key: rsa.RSAPublicKey, signature: bytes, data: bytes
) -> bool:
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), SHA256())
        return True
    except InvalidSignature:
        return False
