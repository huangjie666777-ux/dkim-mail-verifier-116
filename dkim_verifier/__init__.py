"""DKIM mail verifier (RFC 6376 subset).

Modules:
- parser: raw message and DKIM-Signature tag-list parsing
- canonicalization: simple/relaxed header and body canonicalization
- keys: RSA public-key store loaded from a local JSON file
- verifier: signature verification orchestration
- app: FastAPI HTTP layer
"""

from .keys import KeyStore
from .verifier import verify_message

__all__ = ["KeyStore", "verify_message"]
