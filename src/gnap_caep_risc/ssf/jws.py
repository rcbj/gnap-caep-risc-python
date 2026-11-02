# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Verify a Security Event Token or an ID token. The key is chosen by kid. none and HMAC are refused."""

import json
import re

from ..errors import GnapError
from ..keys import public_key_from_jwk, verify_raw
from ..codec import b64url_decode

ALGS = {
    "RS256": {"kty": "RSA"},
    "RS384": {"kty": "RSA"},
    "RS512": {"kty": "RSA"},
    "PS256": {"kty": "RSA"},
    "PS384": {"kty": "RSA"},
    "PS512": {"kty": "RSA"},
    "ES256": {"kty": "EC"},
    "ES384": {"kty": "EC"},
    "ES512": {"kty": "EC"},
    "EdDSA": {"kty": "OKP"},
    "Ed25519": {"kty": "OKP"},
}
SUPPORTED_JWS_ALGS = list(ALGS)


def _b64(value: str, what: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value or ""):
        raise GnapError("signature", f"the JWS {what} is not base64url")
    return b64url_decode(value)


def verify_compact_jws(token: str, keys) -> dict:
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        raise GnapError("signature", "the token is not a compact JWS")
    header_b, payload_b, sig_b = parts
    try:
        header = json.loads(_b64(header_b, "header").decode("utf-8"))
        payload = json.loads(_b64(payload_b, "payload").decode("utf-8"))
    except GnapError:
        raise
    except Exception as err:
        raise GnapError("signature", "the token's header or payload is not JSON", cause=err) from err
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise GnapError("signature", "the token's header or payload is not a JSON object")
    alg = str(header.get("alg") or "")
    spec = ALGS.get(alg)
    if not spec:
        raise GnapError("signature", f"the token is signed with {alg or '(no alg)'}, which this client does not verify ({', '.join(SUPPORTED_JWS_ALGS)})")
    if "crit" in header:
        raise GnapError("signature", "the token's header has a crit member this client does not understand")
    kid = header.get("kid") if isinstance(header.get("kid"), str) else None
    candidates = [
        key for key in keys
        if (kid is None or key.get("kid") == kid)
        and key.get("kty") == spec["kty"]
        and (not key.get("use") or key.get("use") == "sig")
        and (not key.get("alg") or key.get("alg") == alg)
    ]
    if not candidates:
        suffix = f" with kid {kid}" if kid else ""
        raise GnapError("signature", f"no {spec['kty']} signing key{suffix} was published")
    data = f"{header_b}.{payload_b}".encode("ascii")
    signature = _b64(sig_b, "signature")
    for jwk in candidates:
        public = public_key_from_jwk(jwk)
        if verify_raw(public, alg, data, signature):
            return {"header": header, "payload": payload}
    raise GnapError("signature", "the token's signature does not verify against the published keys")
