# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Subject information from a grant response. An id_token is checked here. HMAC and none are refused."""

import time

from .errors import GnapError
from .ssf.jws import verify_compact_jws


class Person:
    def __init__(self, sub, claims, assertion_verified, iss=None, uid=None, email=None, name=None,
                 preferred_username=None, sid=None, acr=None, amr=None):
        self.sub = sub
        self.claims = claims
        self.assertion_verified = assertion_verified
        self.iss = iss
        self.uid = uid
        self.email = email
        self.name = name
        self.preferred_username = preferred_username
        self.sid = sid
        self.acr = acr
        self.amr = amr


def _strings(value):
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def uid_from_account(uri: str):
    import re
    from urllib.parse import unquote

    match = re.fullmatch(r"acct:([^@]+)@(.+)", uri)
    if not match:
        return None
    user = match.group(1)
    try:
        return _decode_uri_component(user)
    except Exception:
        return user


def _decode_uri_component(value: str) -> str:
    out = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            hexpart = value[index + 1:index + 3]
            if len(hexpart) < 2 or any(item not in "0123456789abcdefABCDEF" for item in hexpart):
                raise ValueError("bad percent-encoding")
            out.append(int(hexpart, 16))
            index += 3
        else:
            encoded = char.encode("utf-8")
            out.extend(encoded)
            index += 1
    return out.decode("utf-8")


def person_from(subject, check):
    if not isinstance(subject, dict):
        return None
    sub_ids = subject.get("sub_ids") if isinstance(subject.get("sub_ids"), list) else []
    iss_sub = next((item for item in sub_ids if isinstance(item, dict) and item.get("format") == "iss_sub" and isinstance(item.get("sub"), str)), None)
    opaque = next((item for item in sub_ids if isinstance(item, dict) and item.get("format") == "opaque" and isinstance(item.get("id"), str)), None)
    account = next((item for item in sub_ids if isinstance(item, dict) and item.get("format") == "account" and isinstance(item.get("uri"), str)), None)
    assertions = subject.get("assertions") if isinstance(subject.get("assertions"), list) else []
    id_token = next((item for item in assertions if isinstance(item, dict) and item.get("format") == "id_token" and isinstance(item.get("value"), str)), None)
    claims = {}
    sub = iss_sub.get("sub") if iss_sub else None
    iss = iss_sub.get("iss") if iss_sub and isinstance(iss_sub.get("iss"), str) else None
    verified = False
    if id_token:
        keys = check["keys"]() if isinstance(check, dict) else check.keys()
        if hasattr(keys, "__await__"):
            raise GnapError("validation", "subject key lookup must be synchronous")
        verified_jws = verify_compact_jws(id_token["value"], keys)
        payload = verified_jws["payload"]
        issuer = check["id_token_issuer"] if isinstance(check, dict) else check.id_token_issuer
        audiences = check["audiences"] if isinstance(check, dict) else check.audiences
        skew = check["clock_tolerance_sec"] if isinstance(check, dict) else check.clock_tolerance_sec
        if payload.get("iss") != issuer:
            raise GnapError("validation", f"the id_token was issued by {payload.get('iss')}, not {issuer}")
        if not isinstance(payload.get("sub"), str) or not payload.get("sub"):
            raise GnapError("validation", "the id_token has no sub")
        if not isinstance(payload.get("exp"), (int, float)) or isinstance(payload.get("exp"), bool):
            raise GnapError("validation", "the id_token has no exp")
        now = int(time.time())
        if payload["exp"] + skew < now:
            raise GnapError("validation", "the id_token has expired")
        nbf = _num(payload.get("nbf"))
        if nbf is not None and nbf - skew > now:
            raise GnapError("validation", "the id_token is not valid yet")
        iat = _num(payload.get("iat"))
        if iat is not None and iat - skew > now:
            raise GnapError("validation", "the id_token is issued in the future")
        aud = _strings(payload.get("aud"))
        known = [item for item in audiences if item]
        if known and not any(one in known for one in aud):
            shown = ", ".join(aud) if aud else "(no audience)"
            raise GnapError("validation", f"the id_token is for {shown}, not {' or '.join(known)}")
        if sub is not None and payload["sub"] != sub:
            raise GnapError("validation", "the id_token is about somebody other than the subject identifier")
        sub = payload["sub"]
        iss = str(payload.get("iss"))
        claims.update(payload)
        verified = True
    if not sub and opaque:
        sub = opaque["id"]
    if not sub and account:
        sub = account["uri"]
    if not sub:
        return None
    uid = uid_from_account(account["uri"]) if account else None
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    name = claims.get("name") if isinstance(claims.get("name"), str) else None
    preferred = claims.get("preferred_username") if isinstance(claims.get("preferred_username"), str) else None
    sid = claims.get("sid") if isinstance(claims.get("sid"), str) else claims.get("session_id") if isinstance(claims.get("session_id"), str) else None
    acr = claims.get("acr") if isinstance(claims.get("acr"), str) else None
    amr = [str(item) for item in claims["amr"]] if isinstance(claims.get("amr"), list) else None
    return Person(sub, claims, verified, iss, uid, email, name, preferred, sid, acr, amr)
