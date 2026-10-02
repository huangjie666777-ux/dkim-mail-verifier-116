"""DKIM-Signature 标签解析与单条签名的验签流程（RFC 6376 子集）。

支持：v=1、a=rsa-sha256、c=simple|relaxed/simple|relaxed（缺省 simple/simple）。
拒绝：l= 部分正文签名、重复/非法标签、不支持的版本与算法。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

from .canonicalize import canonicalize_body, canonicalize_header
from .crypto import verify_rsa_sha256
from .keystore import KeyLookupError, KeyStore
from .parser import ParsedMessage

_FWS = b" \t\r\n"
_TAG_NAME_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]*")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_REQUIRED_TAGS = ("v", "a", "b", "bh", "d", "h", "s")


class SignatureError(Exception):
    """DKIM-Signature 存在明确错误，信息可直接返回给调用方。"""


@dataclass
class SignatureResult:
    domain: str | None = None
    selector: str | None = None
    canonicalization: str | None = None
    signed_headers: list[str] = field(default_factory=list)  # h= 列出的字段
    covered_headers: list[str] = field(default_factory=list)  # 实际参与验签的字段
    body_hash_match: bool | None = None
    result: str = "error"  # pass | fail | error
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "selector": self.selector,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "covered_headers": self.covered_headers,
            "body_hash_match": self.body_hash_match,
            "result": self.result,
            "reason": self.reason,
        }


def parse_dkim_header(raw: bytes) -> tuple[dict[str, str], tuple[int, int]]:
    """解析 DKIM-Signature 原始字节（含结尾 CRLF）。

    返回 (tags, b_span)：tags 为去空白后的标签字典；
    b_span 为 b 标签值在 raw 中的绝对字节区间（含其前后折行空白），
    供验签时仅清空 b 值、其余字节原样保留。
    """
    colon = raw.find(b":")
    if colon == -1:
        raise SignatureError("malformed DKIM-Signature header")
    value_offset = colon + 1
    value = raw[value_offset:]
    if value.endswith(b"\r\n"):
        value = value[:-2]

    tags: dict[str, str] = {}
    b_span: tuple[int, int] | None = None
    pos, n = 0, len(value)
    while True:
        while pos < n and value[pos] in _FWS:
            pos += 1
        if pos >= n:
            break
        match = _TAG_NAME_RE.match(value, pos)
        if not match:
            raise SignatureError(
                f"invalid tag syntax at offset {pos} in DKIM-Signature"
            )
        name = match.group().decode("ascii").lower()
        pos = match.end()
        while pos < n and value[pos] in _FWS:
            pos += 1
        if pos >= n or value[pos] != 0x3D:  # '='
            raise SignatureError(f"missing '=' after tag {name!r}")
        pos += 1
        value_start = pos  # 从 '=' 之后算起，含值前的折行空白
        while pos < n and value[pos] in _FWS:
            pos += 1
        while pos < n and value[pos] != 0x3B:  # ';'
            pos += 1
        value_end = pos
        if pos < n:
            pos += 1  # 消费 ';'
        try:
            cleaned = re.sub(rb"[ \t\r\n]", b"", value[value_start:value_end]).decode(
                "ascii"
            )
        except UnicodeDecodeError:
            raise SignatureError(f"tag {name!r} contains non-ASCII bytes")
        if name in tags:
            raise SignatureError(f"duplicate tag {name!r} in DKIM-Signature")
        tags[name] = cleaned
        if name == "b":
            b_span = (value_offset + value_start, value_offset + value_end)
    if b_span is None:
        # b 是必需标签，此处缺失会在校验阶段报 missing；给个占位避免越界
        b_span = (0, 0)
    return tags, b_span


def select_headers(
    msg: ParsedMessage, sig_index: int, h_names: list[str]
) -> list:
    """按 h= 列表顺序，从头部底部向上逐次选取同名字段。

    每个已出现的字段只被消费一次；列表中缺失的字段允许跳过（超额列出）。
    当前 DKIM-Signature 字段自身不参与选取。
    """
    used: set[int] = set()
    selected = []
    for name in h_names:
        for i in range(len(msg.headers) - 1, -1, -1):
            if i == sig_index or i in used:
                continue
            if msg.headers[i].name.lower() == name:
                used.add(i)
                selected.append(msg.headers[i])
                break
        # 未找到：视为超额列出，按 RFC 允许
    return selected


def verify_signature(
    msg: ParsedMessage, sig_index: int, keystore: KeyStore
) -> SignatureResult:
    """验签单条 DKIM-Signature；任何错误都只影响本条结果。"""
    result = SignatureResult()
    raw = msg.headers[sig_index].raw
    try:
        tags, b_span = parse_dkim_header(raw)
        header_c, body_c = _validate_tags(tags, result)

        # 1) 正文摘要：按传输字节计算，不解码 MIME
        digest = hashlib.sha256(canonicalize_body(msg.body, body_c)).digest()
        expected_bh = _b64decode(tags["bh"], "bh")
        result.body_hash_match = digest == expected_bh

        # 2) 头部散列输入：h= 选出的字段 + 仅清空 b 值的本签名头
        selected = select_headers(msg, sig_index, result.signed_headers)
        result.covered_headers = [f.name for f in selected]
        hash_input = b"".join(
            canonicalize_header(f.name, f.raw, header_c) for f in selected
        )
        emptied = raw[: b_span[0]] + raw[b_span[1]:]
        hash_input += canonicalize_header("DKIM-Signature", emptied, header_c)

        # 3) RSA PKCS#1 v1.5 + SHA-256 验签（不能仅凭正文摘要判通过）
        signature = _b64decode(tags["b"], "b")
        if not signature:
            raise SignatureError("empty b= signature value")
        public_key = keystore.get(result.domain, result.selector)
        signature_ok = verify_rsa_sha256(public_key, signature, hash_input)

        if signature_ok and result.body_hash_match:
            result.result = "pass"
        else:
            result.result = "fail"
            problems = []
            if not result.body_hash_match:
                problems.append("body hash mismatch")
            if not signature_ok:
                problems.append("RSA signature verification failed")
            result.reason = "; ".join(problems)
    except (SignatureError, KeyLookupError) as exc:
        result.result = "error"
        result.reason = str(exc)
    return result


def _validate_tags(tags: dict[str, str], result: SignatureResult):
    """校验标签合法性，填充 result 的元信息，返回 (header_c, body_c)。"""
    missing = [t for t in _REQUIRED_TAGS if t not in tags]
    if missing:
        raise SignatureError(f"missing required tag(s): {', '.join(missing)}")

    result.domain = tags["d"]
    result.selector = tags["s"]
    if not result.domain:
        raise SignatureError("empty d= tag")
    if not result.selector:
        raise SignatureError("empty s= tag")

    if tags["v"] != "1":
        raise SignatureError(f"unsupported version v={tags['v']!r} (only v=1)")
    if tags["a"].lower() != "rsa-sha256":
        raise SignatureError(
            f"unsupported algorithm a={tags['a']!r} (only rsa-sha256)"
        )

    c = tags.get("c", "simple/simple").lower()
    parts = c.split("/")
    if len(parts) == 1:
        parts.append("simple")
    if (
        len(parts) != 2
        or parts[0] not in ("simple", "relaxed")
        or parts[1] not in ("simple", "relaxed")
    ):
        raise SignatureError(f"unsupported canonicalization c={c!r}")
    result.canonicalization = f"{parts[0]}/{parts[1]}"

    if "l" in tags:
        raise SignatureError("partial body signatures (l= tag) are not accepted")

    h_names = [n for n in (x.strip().lower() for x in tags["h"].split(":")) if n]
    if not h_names:
        raise SignatureError("empty h= tag")
    for name in h_names:
        if not _HEADER_NAME_RE.match(name):
            raise SignatureError(f"invalid header name {name!r} in h= tag")
    if "from" not in h_names:
        raise SignatureError("h= tag does not cover the mandatory From header")
    result.signed_headers = h_names

    return parts[0], parts[1]


def _b64decode(value: str, tag: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError(f"invalid base64 in {tag}= tag")
