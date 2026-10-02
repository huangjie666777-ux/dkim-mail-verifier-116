"""Parsing of raw RFC 5322 messages and DKIM-Signature tag lists.

The parser preserves the original byte layout of header fields (including
folding whitespace and duplicate fields) so that "simple" canonicalization
can operate on the exact bytes that were received.
"""

from __future__ import annotations

from dataclasses import dataclass


class MessageParseError(ValueError):
    """Raised when a message cannot be parsed as a CRLF-delimited mail."""


@dataclass(frozen=True)
class Header:
    """A single header field.

    :param name: field name as received (without the colon)
    :param raw: full field bytes as received, including name, colon, value
        and any folding CRLFs; always ends with the field's own CRLF
    """

    name: bytes
    raw: bytes


def split_message(raw: bytes) -> tuple[list[Header], bytes]:
    """Split a raw message into header fields and body.

    The message must use CRLF line endings: every LF MUST be preceded by
    CR and every CR MUST be followed by LF. Returns ``(headers, body)``.
    """
    _validate_crlf(raw)
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return _parse_header_block(raw), b""
    return _parse_header_block(raw[:sep]), raw[sep + 4 :]


def _validate_crlf(raw: bytes) -> None:
    for i, byte in enumerate(raw):
        if byte == 0x0A and (i == 0 or raw[i - 1] != 0x0D):
            raise MessageParseError(
                "message contains a bare LF; only CRLF line endings are accepted"
            )
        if byte == 0x0D and (i + 1 >= len(raw) or raw[i + 1] != 0x0A):
            raise MessageParseError(
                "message contains a bare CR; only CRLF line endings are accepted"
            )


def _parse_header_block(header_block: bytes) -> list[Header]:
    if not header_block:
        return []
    headers: list[Header] = []
    current_name: bytes | None = None
    current_raw = b""
    for line in header_block.split(b"\r\n"):
        if line and line[0] in (0x20, 0x09):  # SP / HTAB -> continuation
            if current_name is None:
                raise MessageParseError("header block starts with folding whitespace")
            current_raw += line + b"\r\n"
            continue
        if current_name is not None:
            headers.append(Header(current_name, current_raw))
        if not line or b":" not in line:
            raise MessageParseError(f"header line without a colon: {line!r}")
        name = line.split(b":", 1)[0]
        if not name:
            raise MessageParseError("header field with an empty name")
        current_name = name
        current_raw = line + b"\r\n"
    if current_name is not None:
        headers.append(Header(current_name, current_raw))
    return headers


# ---------------------------------------------------------------------------
# DKIM-Signature tag list parsing (RFC 6376 section 3.2)
# ---------------------------------------------------------------------------


def parse_signature_tags(value: bytes) -> dict[bytes, bytes]:
    """Parse a DKIM-Signature field value into a tag dict.

    Folding whitespace is unfolded first. Duplicate tags and malformed
    tags raise :class:`MessageParseError`. Unknown tags are returned as-is
    and ignored later by the verifier, as required by RFC 6376.
    """
    unfolded = _unfold(value)
    tags: dict[bytes, bytes] = {}
    for part in unfolded.split(b";"):
        part = part.strip(b" \t")
        if not part:
            continue  # trailing semicolon / empty tag
        name, sep, tag_value = part.partition(b"=")
        name = name.strip(b" \t")
        tag_value = tag_value.strip(b" \t")
        if not sep or not name:
            raise MessageParseError(f"malformed signature tag: {part!r}")
        if not _is_valid_tag_name(name):
            raise MessageParseError(f"invalid signature tag name: {name!r}")
        if name in tags:
            raise MessageParseError(f"duplicate signature tag: {name!r}")
        tags[name] = tag_value
    return tags


def _unfold(value: bytes) -> bytes:
    """Remove CRLF sequences that are followed by WSP (folding)."""
    out = bytearray()
    i = 0
    n = len(value)
    while i < n:
        if (
            value[i] == 0x0D
            and i + 2 < n
            and value[i + 1] == 0x0A
            and value[i + 2] in (0x20, 0x09)
        ):
            out.append(value[i + 2])
            i += 3
        else:
            out.append(value[i])
            i += 1
    return bytes(out)


def _is_valid_tag_name(name: bytes) -> bool:
    return bool(name) and all(
        (0x30 <= c <= 0x39)  # 0-9
        or (0x41 <= c <= 0x5A)  # A-Z
        or (0x61 <= c <= 0x61 + 25)  # a-z
        or c == 0x5F  # underscore
        for c in name
    )
