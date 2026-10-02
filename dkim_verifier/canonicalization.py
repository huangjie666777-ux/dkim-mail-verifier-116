"""Header and body canonicalization (RFC 6376 section 3.4).

The DKIM-Signature field being verified is canonicalized like any other
header field, but with the value of its ``b=`` tag emptied. It is fed to
the hash algorithm *after* the ``h=``-selected fields and without a
trailing CRLF (RFC 6376 section 3.7, hash step 2).
"""

from __future__ import annotations

import re

from .parser import Header

_WSP = b" \t"


def canonicalize_header(header: Header, mode: str, *, is_signature: bool) -> bytes:
    """Return the canonicalized bytes of a single header field.

    The returned bytes always end with the field's own CRLF; the caller
    strips it for the DKIM-Signature field (hash step 2).
    """
    if mode == "simple":
        return _simple_header(header, is_signature=is_signature)
    return _relaxed_header(header, is_signature=is_signature)


def _simple_header(header: Header, *, is_signature: bool) -> bytes:
    raw = header.raw
    if is_signature:
        prefix = header.name + b":"
        value = header.raw[len(prefix) :]
        start, end = _tag_value_span(value, b"b")
        if start >= 0:
            raw = header.raw[: len(prefix) + start] + header.raw[len(prefix) + end :]
    return raw


def _relaxed_header(header: Header, *, is_signature: bool) -> bytes:
    name = header.name.lower()
    _, _, value = header.raw.partition(b":")
    value = _unfold(value)
    # Separate the field's terminating CRLF from its value content so that
    # trailing WSP can be deleted from the value itself.
    if value.endswith(b"\r\n"):
        content = value[:-2]
        terminator = b"\r\n"
    else:
        content = value
        terminator = b""
    if is_signature:
        start, end = _tag_value_span(content, b"b")
        if start >= 0:
            content = content[:start] + content[end:]
    # RFC 3.4.2 step 3: WSP sequences -> single SP
    content = re.sub(rb"[ \t]+", b" ", content)
    # RFC 3.4.2 step 4: delete trailing WSP
    content = content.rstrip(_WSP)
    # RFC 3.4.2 step 5: delete WSP remaining before and after the colon
    name = name.rstrip(_WSP)
    content = content.lstrip(_WSP)
    return name + b":" + content + terminator


def canonicalize_body(body: bytes, mode: str) -> bytes:
    """Return the canonicalized body bytes."""
    if mode == "simple":
        return _simple_body(body)
    return _relaxed_body(body)


def _simple_body(body: bytes) -> bytes:
    # RFC 3.4.3: collapse trailing empty lines to a single CRLF.
    result = body
    while result.endswith(b"\r\n"):
        prefix = result[:-2]
        if prefix.endswith(b"\r\n") or not prefix:
            result = prefix
        else:
            break
    if not result.endswith(b"\r\n"):
        result += b"\r\n"
    return result


def _relaxed_body(body: bytes) -> bytes:
    if not body:
        return b""
    lines = body.split(b"\r\n")
    canonical: list[bytes] = []
    for line in lines:
        # RFC 3.4.4 (a): reduce WSP, then ignore trailing WSP.
        canonical.append(re.sub(rb"[ \t]+", b" ", line).rstrip(_WSP))
    # RFC 3.4.4 (b): ignore trailing empty lines.
    while canonical and canonical[-1] == b"":
        canonical.pop()
    if not canonical:
        return b""
    return b"\r\n".join(canonical) + b"\r\n"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _unfold(value: bytes) -> bytes:
    """Remove CRLF sequences that are followed by WSP (folding)."""
    return re.sub(rb"\r\n(?=[ \t])", b"", value)


def _skip_fws(value: bytes, pos: int) -> int:
    """Skip folding whitespace (WSP and CRLF+WSP) starting at ``pos``."""
    n = len(value)
    while pos < n:
        if value[pos] in _WSP:
            pos += 1
        elif (
            value[pos] == 0x0D
            and pos + 2 < n
            and value[pos + 1] == 0x0A
            and value[pos + 2] in _WSP
        ):
            pos += 3
        else:
            break
    return pos


def _tag_value_span(value: bytes, tag: bytes) -> tuple[int, int]:
    """Return the (start, end) byte span of a tag's value in a header value.

    The span starts right after ``tag=`` and ends before the next ``;`` or
    the field's terminating CRLF. Folding CRLFs inside the value are part
    of the span. Returns ``(-1, -1)`` if the tag is not present.
    """
    tag = tag.lower()
    n = len(value)
    pos = 0
    while pos < n:
        pos = _skip_fws(value, pos)
        if pos >= n:
            break
        name_start = pos
        while pos < n and value[pos] not in b"=; \t":
            pos += 1
        name = value[name_start:pos].lower()
        pos = _skip_fws(value, pos)
        if pos >= n or value[pos] != 0x3D:  # '='
            while pos < n and value[pos] != 0x3B:  # skip to ';'
                pos += 1
            if pos < n:
                pos += 1
            continue
        pos += 1  # skip '='
        val_start = pos
        while pos < n:
            if value[pos] == 0x3B:  # ';'
                break
            if value[pos] == 0x0D and pos + 1 < n and value[pos + 1] == 0x0A:
                if pos + 2 < n and value[pos + 2] in _WSP:
                    pos += 3  # folding inside the value
                    continue
                break  # field terminator
            pos += 1
        val_end = pos
        if name == tag:
            return val_start, val_end
        pos += 1  # skip past ';'
    return -1, -1
