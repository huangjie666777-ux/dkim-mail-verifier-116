"""RFC 6376 子集的头部/正文规范化（simple 与 relaxed）。"""
from __future__ import annotations

import re

_WSP_RUN = re.compile(rb"[ \t]+")


def canonicalize_body(body: bytes, mode: str) -> bytes:
    if mode == "simple":
        return _body_simple(body)
    if mode == "relaxed":
        return _body_relaxed(body)
    raise ValueError(f"unknown body canonicalization: {mode}")


def canonicalize_header(name: str, raw: bytes, mode: str) -> bytes:
    """raw 为含结尾 CRLF 的完整原始头部字段字节。"""
    if mode == "simple":
        # simple：原样使用，逐字节保留（含折行与结尾 CRLF）
        return raw
    if mode == "relaxed":
        return _header_relaxed(name, raw)
    raise ValueError(f"unknown header canonicalization: {mode}")


def _body_simple(body: bytes) -> bytes:
    # 忽略正文末尾所有空行；非空时保证恰好以一个 CRLF 结尾；空正文为空串
    lines = body.split(b"\r\n")
    while lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        return b""
    return b"\r\n".join(lines) + b"\r\n"


def _body_relaxed(body: bytes) -> bytes:
    # 每行：压缩行内 WSP 为单个空格、去掉行尾 WSP；忽略末尾空行
    lines = body.split(b"\r\n")
    out = []
    for line in lines:
        line = _WSP_RUN.sub(b" ", line.rstrip(b" \t"))
        out.append(line)
    while out and out[-1] == b"":
        out.pop()
    if not out:
        return b""
    return b"\r\n".join(out) + b"\r\n"


def _header_relaxed(name: str, raw: bytes) -> bytes:
    # 字段名转小写；展开折行；WSP 压缩为单个空格；去首尾空格；补一个 CRLF
    colon = raw.find(b":")
    value = raw[colon + 1:]
    if value.endswith(b"\r\n"):
        value = value[:-2]
    value = value.replace(b"\r\n", b"")  # 续行必以 WSP 开头，去 CRLF 即展开
    value = _WSP_RUN.sub(b" ", value).strip(b" ")
    return name.lower().encode("ascii") + b":" + value + b"\r\n"
