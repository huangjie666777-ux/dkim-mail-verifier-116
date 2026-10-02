"""RSA public-key store loaded from a local JSON file.

The JSON file maps domains to selectors to PEM-encoded public keys::

    {
      "example.com": {
        "selector1": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n"
      }
    }

A top-level ``{"keys": {...}}`` wrapper is also accepted. No network or
DNS access is performed; keys never leave the local process.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key


class KeyStoreError(ValueError):
    """Raised when the key store configuration is invalid."""


class KeyStore:
    def __init__(self, keys: dict[str, dict[str, bytes]]):
        self._keys = keys

    @classmethod
    def load(cls, path: str | Path) -> "KeyStore":
        """Load and validate the key store from a JSON file."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyStoreError(f"cannot read key store {path!r}: {exc}") from exc
        if not isinstance(data, dict):
            raise KeyStoreError("key store must be a JSON object")
        raw = data.get("keys", data)
        if not isinstance(raw, dict):
            raise KeyStoreError("key store 'keys' must be a JSON object")

        keys: dict[str, dict[str, bytes]] = {}
        for domain, selectors in raw.items():
            if not isinstance(selectors, dict):
                raise KeyStoreError(f"key entry for domain {domain!r} must be an object")
            bucket = keys.setdefault(str(domain).lower(), {})
            for selector, pem in selectors.items():
                pem_bytes = _coerce_pem(pem, domain, selector)
                bucket[str(selector).lower()] = pem_bytes
        return cls(keys)

    def get(self, domain: str, selector: str) -> bytes | None:
        """Return the PEM bytes for (domain, selector), or None if unknown."""
        return self._keys.get(domain.lower(), {}).get(selector.lower())


def _coerce_pem(pem: object, domain: str, selector: str) -> bytes:
    if isinstance(pem, str):
        pem_bytes = pem.encode("ascii")
    elif isinstance(pem, bytes):
        pem_bytes = pem
    else:
        raise KeyStoreError(
            f"key for domain={domain!r} selector={selector!r} must be a PEM string"
        )
    try:
        load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise KeyStoreError(
            f"invalid PEM public key for domain={domain!r} selector={selector!r}: {exc}"
        ) from exc
    return pem_bytes
