"""DKIM-Signature verification (RFC 6376 subset).

Supports v=1, rsa-sha256, and simple/relaxed header and body
canonicalization. Partial body signatures (l=) are rejected. Each
DKIM-Signature field is verified independently; a failure in one does not
block the others.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .canonicalization import canonicalize_body, canonicalize_header
from .keys import KeyStore, KeyStoreError
from .parser import Header, MessageParseError, parse_signature_tags, split_message

_SUPPORTED_SIGN_ALG = b"rsa-sha256"
_SUPPORTED_VERSION = b"1"


class VerificationError(ValueError):
    """Raised when a signature cannot be verified."""


@dataclass
class SignatureResult:
    index: int
    domain: str | None = None
    selector: str | None = None
    header_canon: str | None = None
    body_canon: str | None = None
    covered_headers: list[str] = field(default_factory=list)
    body_hash_match: bool | None = None
    status: str = "error"  # "pass" | "fail" | "error"
    reason: str | None = None


def verify_message(
    raw: bytes,
    key_store: KeyStore,
    *,
    max_headers: int = 100,
    max_signatures: int = 10,
) -> dict:
    """Verify all DKIM-Signature fields in a raw message."""
    try:
        headers, body = split_message(raw)
    except MessageParseError as exc:
        return {"status": "error", "reason": str(exc), "signatures": []}

    if len(headers) > max_headers:
        return {
            "status": "error",
            "reason": f"too many header fields: {len(headers)} > {max_headers}",
            "signatures": [],
        }

    sig_positions = [
        i for i, h in enumerate(headers) if h.name.lower() == b"dkim-signature"
    ]
    if not sig_positions:
        return {"status": "no_signature", "signatures": []}
    if len(sig_positions) > max_signatures:
        return {
            "status": "error",
            "reason": f"too many DKIM-Signature fields: {len(sig_positions)} > {max_signatures}",
            "signatures": [],
        }

    results = [
        _verify_one(headers, body, position, index, key_store)
        for index, position in enumerate(sig_positions)
    ]
    overall = "pass" if all(r.status == "pass" for r in results) else "fail"
    return {"status": overall, "signatures": [_result_to_dict(r) for r in results]}


def _result_to_dict(result: SignatureResult) -> dict:
    return {
        "index": result.index,
        "domain": result.domain,
        "selector": result.selector,
        "canonicalization": {
            "header": result.header_canon,
            "body": result.body_canon,
        },
        "covered_headers": result.covered_headers,
        "body_hash_match": result.body_hash_match,
        "status": result.status,
        "reason": result.reason,
    }


def _verify_one(
    headers: list[Header],
    body: bytes,
    sig_position: int,
    index: int,
    key_store: KeyStore,
) -> SignatureResult:
    result = SignatureResult(index=index)
    sig_header = headers[sig_position]
    try:
        tags = parse_signature_tags(sig_header.raw.partition(b":")[2])
        _validate_tags(tags)

        domain = _decode_ascii(tags[b"d"], "d= domain tag")
        selector = _decode_ascii(tags[b"s"], "s= selector tag")
        result.domain = domain
        result.selector = selector

        header_canon, body_canon = _parse_canon(tags.get(b"c", b"simple/simple"))
        result.header_canon = header_canon
        result.body_canon = body_canon

        h_names = _parse_h_list(tags[b"h"])
        result.covered_headers = [name.decode("ascii") for name in h_names]
        if b"from" not in h_names:
            raise VerificationError("h= tag does not include the From header field")

        pem = key_store.get(domain, selector)
        if pem is None:
            raise VerificationError(
                f"no public key registered for domain={domain!r} selector={selector!r}"
            )
        public_key = load_pem_public_key(pem)

        # Body hash (hash step 1): over transport bytes, no MIME decoding.
        canonical_body = canonicalize_body(body, body_canon)
        actual_bh = hashlib.sha256(canonical_body).digest()
        expected_bh = _b64decode(tags[b"bh"], "bh=")
        result.body_hash_match = actual_bh == expected_bh

        # Header hash (hash step 2): h= fields each + CRLF, then the
        # DKIM-Signature field with b= emptied and no trailing CRLF.
        selected = _select_headers(headers, h_names, sig_position)
        hash_input = b"".join(
            canonicalize_header(h, header_canon, is_signature=False) for h in selected
        )
        sig_field = canonicalize_header(sig_header, header_canon, is_signature=True)
        if sig_field.endswith(b"\r\n"):
            sig_field = sig_field[:-2]  # hash step 2: no trailing CRLF
        hash_input += sig_field

        signature = _b64decode(tags[b"b"], "b=")
        try:
            public_key.verify(signature, hash_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            result.status = "fail"
            result.reason = "RSA signature verification failed"
            return result

        if not result.body_hash_match:
            result.status = "fail"
            result.reason = "body hash mismatch"
        else:
            result.status = "pass"
        return result
    except (VerificationError, MessageParseError, KeyStoreError) as exc:
        result.status = "error"
        result.reason = str(exc)
        return result


def _validate_tags(tags: dict[bytes, bytes]) -> None:
    if tags.get(b"v") != _SUPPORTED_VERSION:
        raise VerificationError(
            f"unsupported version: v={tags.get(b'v', b'').decode('ascii', 'replace')!r}"
            " (only v=1 is supported)"
        )
    if tags.get(b"a") != _SUPPORTED_SIGN_ALG:
        raise VerificationError(
            f"unsupported algorithm: a={tags.get(b'a', b'').decode('ascii', 'replace')!r}"
            " (only rsa-sha256 is supported)"
        )
    for required in (b"b", b"bh", b"d", b"s", b"h"):
        if not tags.get(required):
            raise VerificationError(f"missing or empty required tag: {required.decode()}=")
    if b"l" in tags:
        raise VerificationError(
            "partial body signatures (l= length tag) are not supported"
        )


def _parse_canon(value: bytes) -> tuple[str, str]:
    parts = [p.strip(b" \t").lower() for p in value.split(b"/")]
    if len(parts) > 2 or any(p not in (b"simple", b"relaxed") for p in parts):
        raise VerificationError(
            f"invalid c= canonicalization tag: {value.decode('ascii', 'replace')!r}"
        )
    if len(parts) == 1:
        return parts[0].decode(), "simple"
    return parts[0].decode(), parts[1].decode()


def _parse_h_list(value: bytes) -> list[bytes]:
    names = []
    for part in value.split(b":"):
        name = part.strip(b" \t").lower()
        if name:
            names.append(name)
    return names


def _select_headers(
    headers: list[Header], h_names: list[bytes], sig_position: int
) -> list[Header]:
    """Select header fields per h=, from the bottom up, consuming each once.

    Fields named in h= that are not present in the message are skipped
    (excess listing is allowed). The DKIM-Signature field being verified
    is excluded from selection.
    """
    available = [h for i, h in enumerate(headers) if i != sig_position]
    selected: list[Header] = []
    for name in h_names:
        for i in range(len(available) - 1, -1, -1):
            if available[i].name.lower() == name:
                selected.append(available.pop(i))
                break
    return selected


def _b64decode(value: bytes, tag: str) -> bytes:
    try:
        return base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(f"invalid base64 in {tag} tag: {exc}") from exc


def _decode_ascii(value: bytes, what: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{what} is not ASCII: {value!r}") from exc
