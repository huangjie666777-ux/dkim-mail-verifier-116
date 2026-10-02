"""Tests for the DKIM verifier.

The signing helper reuses the package's own canonicalization code so that
a passing test also cross-checks the verifier against a known-good signer.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from dkim_verifier.app import create_app
from dkim_verifier.canonicalization import canonicalize_body, canonicalize_header
from dkim_verifier.keys import KeyStore
from dkim_verifier.parser import Header
from dkim_verifier.verifier import verify_message


@pytest.fixture
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def key_store(private_key):
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyStore({"example.com": {"selector1": pem}})


def _sign(
    private_key,
    headers: list[tuple[str, str]],
    body: bytes,
    *,
    domain: str = "example.com",
    selector: str = "selector1",
    header_canon: str = "simple",
    body_canon: str = "simple",
    h_fields: list[str] | None = None,
    extra_tags: str = "",
) -> bytes:
    """Build a raw message with a valid DKIM-Signature field."""
    if h_fields is None:
        h_fields = [name for name, _ in headers]

    canonical_body = canonicalize_body(body, body_canon)
    bh = base64.b64encode(hashlib.sha256(canonical_body).digest()).decode()

    h_list = ":".join(h_fields)
    sig_value = (
        f"v=1; a=rsa-sha256; d={domain}; s={selector}; "
        f"c={header_canon}/{body_canon}; h={h_list}; bh={bh}; "
    )
    if extra_tags:
        sig_value += extra_tags + "; "
    sig_value += "b="

    # Select h= headers from the bottom up, mirroring the verifier.
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
        canonicalize_header(h, header_canon, is_signature=False) for h in selected
    )
    hash_input += canonicalize_header(sig_header, header_canon, is_signature=True)[:-2]
    signature = private_key.sign(hash_input, padding.PKCS1v15(), hashes.SHA256())

    sig_value_full = sig_value + base64.b64encode(signature).decode()
    raw_headers = b"".join(
        name.encode() + b":" + value.encode() + b"\r\n" for name, value in headers
    )
    return (
        b"DKIM-Signature:" + sig_value_full.encode() + b"\r\n" + raw_headers + b"\r\n" + body
    )


def _result(raw, key_store, **kwargs):
    return verify_message(raw, key_store, **kwargs)


# ---------------------------------------------------------------------------
# valid signatures
# ---------------------------------------------------------------------------


def test_valid_simple_simple(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com"), ("To", "rcpt@example.com"), ("Subject", "hi")],
        b"hello world\r\n",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"
    sig = result["signatures"][0]
    assert sig["domain"] == "example.com"
    assert sig["selector"] == "selector1"
    assert sig["canonicalization"]["header"] == "simple"
    assert sig["canonicalization"]["body"] == "simple"
    assert sig["body_hash_match"] is True
    assert sig["status"] == "pass"
    assert sig["covered_headers"] == ["from", "to", "subject"]


def test_valid_relaxed_relaxed_with_folding(key_store, private_key):
    raw = _sign(
        private_key,
        [
            ("From", "sender@example.com"),
            ("Subject", "  hello\r\n\tworld  "),
        ],
        b"line1\r\nline2\r\n",
        header_canon="relaxed",
        body_canon="relaxed",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"
    assert result["signatures"][0]["canonicalization"]["header"] == "relaxed"
    assert result["signatures"][0]["canonicalization"]["body"] == "relaxed"


def test_valid_empty_body(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"
    assert result["signatures"][0]["body_hash_match"] is True


def test_valid_body_with_trailing_blank_lines(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"line1\r\n\r\n\r\n",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"


def test_valid_body_without_trailing_crlf(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"line1",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"


def test_excess_h_listing_allowed(key_store, private_key):
    # h= lists From twice but the message has only one From; the second
    # listing is skipped.
    raw = _sign(
        private_key,
        [("From", "sender@example.com"), ("To", "rcpt@example.com")],
        b"body\r\n",
        h_fields=["From", "From", "To", "Date"],
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"
    assert result["signatures"][0]["covered_headers"] == [
        "from",
        "from",
        "to",
        "date",
    ]


def test_unknown_tag_ignored(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        extra_tags="xunknown=whatever",
    )
    result = _result(raw, key_store)
    assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# tampering
# ---------------------------------------------------------------------------


def test_body_tampered_fails(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"original body\r\n",
    )
    tampered = raw.replace(b"original body", b"tampered body", 1)
    result = _result(tampered, key_store)
    assert result["status"] == "fail"
    sig = result["signatures"][0]
    assert sig["status"] == "fail"
    assert sig["body_hash_match"] is False
    assert "body hash mismatch" in sig["reason"]


def test_header_tampered_fails(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com"), ("Subject", "original")],
        b"body\r\n",
    )
    tampered = raw.replace(b"Subject:original", b"Subject:tampered", 1)
    result = _result(tampered, key_store)
    assert result["status"] == "fail"
    sig = result["signatures"][0]
    assert sig["status"] == "fail"
    assert sig["body_hash_match"] is True  # body untouched
    assert "signature verification failed" in sig["reason"]


def test_signature_truncated_fails(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    # Cut the base64 signature short.
    head, _, tail = raw.rpartition(b"\r\nFrom:")
    sig_part = head.split(b"b=")[1]
    tampered = head.split(b"b=")[0] + b"b=" + sig_part[:20] + b"\r\nFrom:" + tail
    result = _result(tampered, key_store)
    assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# invalid signatures / configuration
# ---------------------------------------------------------------------------


def test_unknown_domain(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@other.com")],
        b"body\r\n",
        domain="other.com",
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    sig = result["signatures"][0]
    assert sig["status"] == "error"
    assert "no public key registered" in sig["reason"]


def test_unknown_selector(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        selector="nope",
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "no public key registered" in result["signatures"][0]["reason"]


def test_duplicate_tag_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        extra_tags="d=other.com",
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "duplicate signature tag" in result["signatures"][0]["reason"]


def test_unsupported_algorithm_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    raw = raw.replace(b"a=rsa-sha256", b"a=rsa-sha1", 1)
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "unsupported algorithm" in result["signatures"][0]["reason"]


def test_unsupported_version_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    raw = raw.replace(b"v=1", b"v=2", 1)
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "unsupported version" in result["signatures"][0]["reason"]


def test_missing_from_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com"), ("To", "rcpt@example.com")],
        b"body\r\n",
        h_fields=["To"],
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "does not include the From" in result["signatures"][0]["reason"]


def test_l_tag_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        extra_tags="l=4",
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "partial body" in result["signatures"][0]["reason"]


def test_malformed_tag_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        extra_tags="=bad",
    )
    result = _result(raw, key_store)
    assert result["status"] == "fail"
    assert "malformed signature tag" in result["signatures"][0]["reason"]


def test_no_signature_identified(key_store):
    raw = b"From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nbody\r\n"
    result = _result(raw, key_store)
    assert result["status"] == "no_signature"
    assert result["signatures"] == []


def test_bare_lf_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    raw = raw.replace(b"\r\n", b"\n")
    result = _result(raw, key_store)
    assert result["status"] == "error"
    assert "bare LF" in result["reason"]


def test_too_many_headers_rejected(key_store, private_key):
    headers = [("From", "sender@example.com")] + [
        (f"X-Hdr-{i}", str(i)) for i in range(101)
    ]
    raw = _sign(private_key, headers, b"body\r\n")
    result = _result(raw, key_store, max_headers=100)
    assert result["status"] == "error"
    assert "too many header fields" in result["reason"]


def test_too_many_signatures_rejected(key_store, private_key):
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    raw = raw.replace(b"DKIM-Signature:", b"DKIM-Signature: v=1;\r\nDKIM-Signature:", 1)
    result = _result(raw, key_store, max_signatures=1)
    assert result["status"] == "error"
    assert "too many DKIM-Signature fields" in result["reason"]


# ---------------------------------------------------------------------------
# multiple signatures
# ---------------------------------------------------------------------------


def test_multiple_signatures_bad_does_not_block_good(key_store, private_key):
    good = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    bad = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
        domain="other.com",
    )
    # Strip the body from the second message and join.
    bad_headers, _, bad_body = bad.partition(b"\r\n\r\n")
    good_headers, _, good_body = good.partition(b"\r\n\r\n")
    combined = bad_headers + b"\r\n" + good_headers + b"\r\n\r\n" + good_body
    result = _result(combined, key_store)
    assert result["status"] == "fail"
    assert len(result["signatures"]) == 2
    statuses = {s["index"]: s["status"] for s in result["signatures"]}
    assert set(statuses.values()) == {"error", "pass"}


# ---------------------------------------------------------------------------
# canonicalization known vectors (RFC 6376 section 3.4.3/3.4.4)
# ---------------------------------------------------------------------------


def test_empty_body_simple_hash():
    assert base64.b64encode(hashlib.sha256(canonicalize_body(b"", "simple")).digest()).decode() == (
        "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
    )


def test_empty_body_relaxed_hash():
    assert base64.b64encode(hashlib.sha256(canonicalize_body(b"", "relaxed")).digest()).decode() == (
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    )


def test_simple_body_trailing_blank_lines():
    assert canonicalize_body(b"a\r\n\r\n", "simple") == b"a\r\n"
    assert canonicalize_body(b"a\r\n", "simple") == b"a\r\n"
    assert canonicalize_body(b"a", "simple") == b"a\r\n"
    assert canonicalize_body(b"", "simple") == b"\r\n"


def test_relaxed_body_whitespace():
    # Leading WSP is reduced to a single SP but preserved; trailing WSP is
    # removed. See RFC 6376 section 3.4.5 example 1.
    assert canonicalize_body(b"a  \r\n\tb\t\tc \r\n", "relaxed") == b"a\r\n b c\r\n"
    assert canonicalize_body(b"a\r\n\r\n", "relaxed") == b"a\r\n"


def test_relaxed_header_known_vector():
    # RFC 6376 section 3.4.5, relaxed header: "B : Y\t\r\n\tZ  \r\n" -> "b:Y Z\r\n"
    h = Header(b"B", b"B : Y\t\r\n\tZ  \r\n")
    assert canonicalize_header(h, "relaxed", is_signature=False) == b"b:Y Z\r\n"


def test_simple_header_preserves_bytes():
    raw = b"Subject:  foo\r\n\tbar \r\n"
    h = Header(b"Subject", raw)
    assert canonicalize_header(h, "simple", is_signature=False) == raw


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


def test_http_verify_endpoint(key_store, private_key):
    app = create_app(key_store=key_store)
    client = TestClient(app)
    raw = _sign(
        private_key,
        [("From", "sender@example.com"), ("Subject", "hello")],
        b"body\r\n",
    )
    response = client.post("/verify", content=raw)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert data["signatures"][0]["domain"] == "example.com"


def test_http_tampered_email(key_store, private_key):
    app = create_app(key_store=key_store)
    client = TestClient(app)
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    tampered = raw.replace(b"body\r\n", b"evil\r\n", 1)
    response = client.post("/verify", content=tampered)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "fail"
    assert data["signatures"][0]["body_hash_match"] is False


def test_http_no_signature(key_store):
    app = create_app(key_store=key_store)
    client = TestClient(app)
    response = client.post(
        "/verify", content=b"From: sender@example.com\r\n\r\nbody\r\n"
    )
    assert response.status_code == 200
    assert response.json()["status"] == "no_signature"


def test_http_too_large(monkeypatch, key_store, private_key):
    monkeypatch.setenv("DKIM_MAX_MESSAGE_SIZE", "1")
    app = create_app(key_store=key_store)
    client = TestClient(app)
    raw = _sign(
        private_key,
        [("From", "sender@example.com")],
        b"body\r\n",
    )
    response = client.post("/verify", content=raw)
    assert response.status_code == 413
    assert "too large" in response.json()["reason"]
