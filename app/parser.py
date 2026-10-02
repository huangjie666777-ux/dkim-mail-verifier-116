"""原始邮件字节流解析。

只做切分，不做任何重建：头部保留原始顺序、折行与重复项，
正文保持传输字节原样（不解码 MIME、不改写任何字节）。
"""
from __future__ import annotations

from dataclasses import dataclass


class MessageParseError(Exception):
    """邮件字节流不符合要求（非 CRLF、头部畸形、超过限制等）。"""


@dataclass
class HeaderField:
    name: str  # 头部字段名（保留原始大小写）
    raw: bytes  # 含结尾 CRLF 的完整原始字节（含折行）


@dataclass
class ParsedMessage:
    headers: list[HeaderField]  # 按出现顺序，重复项各自保留
    body: bytes  # 传输层原始正文字节


def parse_message(data: bytes, max_headers: int = 500) -> ParsedMessage:
    _require_crlf_only(data)
    sep = data.find(b"\r\n\r\n")
    if sep == -1:
        raise MessageParseError("missing CRLF CRLF separator between headers and body")
    head = data[:sep] + b"\r\n"
    body = data[sep + 4:]
    headers = _parse_headers(head, max_headers)
    return ParsedMessage(headers=headers, body=body)


def _require_crlf_only(data: bytes) -> None:
    """仅接受 CRLF 换行的邮件：出现裸 LF 或裸 CR 即拒绝。"""
    for i, byte in enumerate(data):
        if byte == 0x0A and (i == 0 or data[i - 1] != 0x0D):
            raise MessageParseError(
                "message contains bare LF; only CRLF line endings are accepted"
            )
        if byte == 0x0D and (i + 1 >= len(data) or data[i + 1] != 0x0A):
            raise MessageParseError(
                "message contains bare CR; only CRLF line endings are accepted"
            )


def _parse_headers(head: bytes, max_headers: int) -> list[HeaderField]:
    # head 以 CRLF 结尾，split 后末尾是空元素，丢弃
    lines = head.split(b"\r\n")[:-1]
    headers: list[HeaderField] = []
    current: bytes | None = None
    for line in lines:
        if line[:1] in (b" ", b"\t"):
            # 折行续行：并入上一个字段，保留原始字节
            if current is None:
                raise MessageParseError(
                    "header continuation line without a preceding header field"
                )
            current += b"\r\n" + line
            continue
        if current is not None:
            headers.append(_make_field(current))
            if len(headers) > max_headers:
                raise MessageParseError(
                    f"too many header fields (limit {max_headers})"
                )
        current = line
    if current is not None:
        headers.append(_make_field(current))
        if len(headers) > max_headers:
            raise MessageParseError(f"too many header fields (limit {max_headers})")
    return headers


def _make_field(raw_line: bytes) -> HeaderField:
    colon = raw_line.find(b":")
    if colon <= 0:
        raise MessageParseError(f"malformed header line: {raw_line[:40]!r}")
    name_bytes = raw_line[:colon]
    try:
        name = name_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise MessageParseError("header name contains non-ASCII bytes")
    if not all(33 <= c <= 126 for c in name_bytes):
        raise MessageParseError(f"invalid header name: {name!r}")
    return HeaderField(name=name, raw=raw_line + b"\r\n")
