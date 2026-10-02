from fastapi.testclient import TestClient

from app.main import create_app
from conftest import BASE_MESSAGE, DOMAIN, H_NAMES, SELECTOR


def verify(client, data: bytes):
    resp = client.post(
        "/verify", content=data, headers={"Content-Type": "message/rfc822"}
    )
    return resp


# ---------- 有效签名 ----------

def test_valid_simple_simple_passes(client, sign):
    resp = verify(client, sign(BASE_MESSAGE))
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "pass"
    sig = body["signatures"][0]
    assert sig["result"] == "pass"
    assert sig["domain"] == DOMAIN
    assert sig["selector"] == SELECTOR
    assert sig["canonicalization"] == "simple/simple"
    assert sig["body_hash_match"] is True
    # h= 列了两个 received，底部向上各消费一次
    assert sig["covered_headers"] == ["Received", "Received", "From", "To", "Subject", "Date"]


def test_valid_relaxed_relaxed_passes(client, sign):
    resp = verify(client, sign(BASE_MESSAGE, header_c="relaxed", body_c="relaxed"))
    sig = resp.json()["signatures"][0]
    assert sig["result"] == "pass"
    assert sig["canonicalization"] == "relaxed/relaxed"


def test_overlisted_missing_header_allowed(client, sign):
    resp = verify(client, sign(BASE_MESSAGE, h_names=H_NAMES + ["x-not-present"]))
    sig = resp.json()["signatures"][0]
    assert sig["result"] == "pass"
    assert "X-Not-Present" not in sig["covered_headers"]


def test_trailing_blank_lines_ignored_simple(client, sign):
    signed = sign(BASE_MESSAGE)
    resp = verify(client, signed + b"\r\n\r\n\r\n")
    assert resp.json()["signatures"][0]["result"] == "pass"


def test_relaxed_body_ignores_extra_whitespace(client, sign):
    signed = sign(BASE_MESSAGE, body_c="relaxed")
    tampered_ws = signed.replace(b"this is a test body.", b"this   is  a test body.  ")
    resp = verify(client, tampered_ws)
    assert resp.json()["signatures"][0]["result"] == "pass"


def test_empty_body_passes(client, sign):
    message = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.org>\r\n"
        b"Date: Thu, 02 Oct 2026 10:00:00 +0000\r\n"
        b"\r\n"
    )
    resp = verify(client, sign(message, h_names=["from", "to", "date"]))
    sig = resp.json()["signatures"][0]
    assert sig["result"] == "pass"
    assert sig["body_hash_match"] is True


# ---------- 篡改与失败 ----------

def test_tampered_body_fails(client, sign):
    signed = sign(BASE_MESSAGE)
    tampered = signed.replace(b"this is a test body.", b"this is a TAMPERED body.")
    body = verify(client, tampered).json()
    sig = body["signatures"][0]
    assert body["overall"] == "fail"
    assert sig["result"] == "fail"
    assert sig["body_hash_match"] is False
    assert "body hash mismatch" in sig["reason"]


def test_tampered_signed_header_fails(client, sign):
    signed = sign(BASE_MESSAGE)
    tampered = signed.replace(b"To: Bob <bob@example.org>", b"To: Eve <eve@example.org>")
    sig = verify(client, tampered).json()["signatures"][0]
    assert sig["result"] == "fail"
    assert sig["body_hash_match"] is True
    assert "RSA signature verification failed" in sig["reason"]


def test_unsigned_header_injection_does_not_break(client, sign):
    # 在顶部追加未签名的头部（模拟转发 MTA），验签仍应通过
    signed = sign(BASE_MESSAGE)
    injected = signed.replace(
        b"Received: from mail.example.com",
        b"X-Forwarded: yes\r\nReceived: from mail.example.com",
        1,
    )
    assert verify(client, injected).json()["signatures"][0]["result"] == "pass"


# ---------- 标签与算法错误 ----------

def test_duplicate_tag_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"v=1; ", b"v=1; v=1; ", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "duplicate tag" in sig["reason"]


def test_invalid_tag_syntax_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"v=1;", b"1bad=1;", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "invalid tag syntax" in sig["reason"]


def test_unsupported_algorithm_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"a=rsa-sha256", b"a=rsa-sha1", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "unsupported algorithm" in sig["reason"]


def test_unsupported_version_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"v=1;", b"v=2;", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "unsupported version" in sig["reason"]


def test_unsupported_canonicalization_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"c=simple/simple", b"c=strict/simple", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "unsupported canonicalization" in sig["reason"]


def test_partial_body_l_tag_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"bh=", b"l=50; bh=", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "l= tag" in sig["reason"]


def test_h_must_cover_from(client, sign):
    signed = sign(BASE_MESSAGE, h_names=["to", "subject", "date"])
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "From" in sig["reason"]


def test_missing_required_tag_rejected(client, sign):
    signed = sign(BASE_MESSAGE).replace(b"s=s1; ", b"", 1)
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "missing required tag" in sig["reason"]


# ---------- 公钥库 ----------

def test_unknown_domain(client, sign):
    signed = sign(BASE_MESSAGE, domain="unknown.example")
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "unknown domain" in sig["reason"]


def test_unknown_selector(client, sign):
    signed = sign(BASE_MESSAGE, selector="nope")
    sig = verify(client, signed).json()["signatures"][0]
    assert sig["result"] == "error"
    assert "unknown selector" in sig["reason"]


# ---------- 多签名与无签名 ----------

def test_multiple_signatures_bad_one_does_not_block(client, sign):
    good = sign(BASE_MESSAGE)
    bad = sign(BASE_MESSAGE, selector="nope")  # 未知 selector 的第二条签名
    # 两条 DKIM-Signature：bad 的放顶部，good 的在其后
    bad_sig_block = bad[: bad.index(b"Received:")]
    combined = bad_sig_block + good
    body = verify(client, combined).json()
    assert body["overall"] == "pass"
    results = {s["selector"]: s["result"] for s in body["signatures"]}
    assert results == {"nope": "error", SELECTOR: "pass"}


def test_no_signature_identified(client):
    body = verify(client, BASE_MESSAGE).json()
    assert body["overall"] == "none"
    assert body["signatures"] == []
    assert "no DKIM-Signature" in body["reason"]


# ---------- 传输与限制 ----------

def test_bare_lf_rejected(client, sign):
    resp = verify(client, sign(BASE_MESSAGE).replace(b"\r\n", b"\n"))
    assert resp.status_code == 400
    assert "bare LF" in resp.json()["detail"]


def test_bare_cr_rejected(client, sign):
    resp = verify(client, sign(BASE_MESSAGE).replace(b"\r\n", b"\r"))
    assert resp.status_code == 400
    assert "bare CR" in resp.json()["detail"]


def test_missing_separator_rejected(client):
    resp = verify(client, b"From: a@b.c\r\nTo: d@e.f\r\n")
    assert resp.status_code == 400


def test_message_size_limit(keystore, sign):
    client = TestClient(create_app(keystore=keystore, max_message_bytes=100))
    resp = verify(client, sign(BASE_MESSAGE))
    assert resp.status_code == 413
    assert "too large" in resp.json()["detail"]


def test_header_count_limit(keystore, sign):
    client = TestClient(create_app(keystore=keystore, max_headers=3))
    resp = verify(client, sign(BASE_MESSAGE))
    assert resp.status_code == 400
    assert "too many header fields" in resp.json()["detail"]


def test_signature_count_limit(keystore, sign):
    client = TestClient(create_app(keystore=keystore, max_signatures=1))
    signed = sign(BASE_MESSAGE)
    sig_block = signed[: signed.index(b"Received:")]
    doubled = sig_block + signed  # 两条相同签名
    body = verify(client, doubled).json()
    assert len(body["signatures"]) == 1
    assert "skipped" in body["note"]
