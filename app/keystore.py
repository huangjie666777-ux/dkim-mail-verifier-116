"""本地 JSON 公钥库：域名 -> selector -> RSA 公钥 PEM。不联网查钥。"""
from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class KeyLookupError(Exception):
    """公钥查找失败（未知域名/selector、PEM 非法等），信息可直接返回给调用方。"""


class KeyStore:
    def __init__(self, path: str):
        with open(path, "rb") as fh:
            data = json.load(fh)
        self._init(data)

    @classmethod
    def from_dict(cls, data: dict) -> "KeyStore":
        store = cls.__new__(cls)
        store._init(data)
        return store

    def _init(self, data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError("key store must be a JSON object of domain -> selector -> PEM")
        self._entries: dict[str, dict[str, str]] = {}
        for domain, selectors in data.items():
            if not isinstance(selectors, dict):
                raise ValueError(f"key store entry for {domain!r} must be an object")
            self._entries[domain.lower()] = dict(selectors)
        self._cache: dict[tuple[str, str], rsa.RSAPublicKey] = {}

    def get(self, domain: str, selector: str) -> rsa.RSAPublicKey:
        cache_key = (domain.lower(), selector)
        if cache_key in self._cache:
            return self._cache[cache_key]
        selectors = self._entries.get(domain.lower())
        if selectors is None:
            raise KeyLookupError(f"unknown domain {domain!r} in key store")
        pem = selectors.get(selector)
        if pem is None:
            raise KeyLookupError(
                f"unknown selector {selector!r} for domain {domain!r} in key store"
            )
        try:
            key = load_pem_public_key(pem.encode("ascii"))
        except Exception:
            raise KeyLookupError(
                f"invalid public key PEM for selector {selector!r} domain {domain!r}"
            )
        if not isinstance(key, rsa.RSAPublicKey):
            raise KeyLookupError(
                f"public key for selector {selector!r} domain {domain!r} is not RSA"
            )
        self._cache[cache_key] = key
        return key
