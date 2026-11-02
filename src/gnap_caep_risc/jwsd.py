# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Detached JWS key proof, RFC 9635 section 7.3.3. The signature covers headerB64 + '.' + payload, not a second encoding."""

import time

from .codec import b64url, dumps, sha256
from .httpsig import _href
from .keys import sign_raw


def ath_of(token: str) -> str:
    return b64url(sha256(token.encode("ascii")))


def detached_jws(key, method, url, body=None, token=None, created=None) -> str:
    header = {
        "typ": "gnap-binding-jwsd",
        "alg": key.alg,
        "kid": key.kid,
        "htm": method.upper(),
        "uri": _href(url),
        "created": int(time.time()) if created is None else created,
    }
    if token:
        header["ath"] = ath_of(token)
    encoded = b64url(dumps(header).encode("utf-8"))
    payload = b64url(sha256(body.encode("utf-8"))) if body else ""
    signature = sign_raw(key, f"{encoded}.{payload}".encode("ascii"))
    return f"{encoded}.{payload}.{b64url(signature)}"
