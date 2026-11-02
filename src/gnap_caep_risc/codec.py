# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Base64 and the small JSON shape this client sends. Bodies are signed as the exact bytes sent."""

import base64
import hashlib
import hmac
import json


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def timing_equal(a: str, b: str) -> bool:
    left = a.encode("utf-8")
    right = b.encode("utf-8")
    return len(left) == len(right) and hmac.compare_digest(left, right)


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)
