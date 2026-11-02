# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""HTTP message signatures (RFC 9421) with an RFC 9530 Content-Digest, for GNAP's httpsig proof.

There is no alg parameter. ECDSA signatures are raw R||S.
"""

import os

from .codec import b64std, sha256
from .keys import sign_raw


def content_digest(body) -> str:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    return f"sha-256=:{b64std(sha256(raw))}:"


def _sf_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def signature_params(components, created, nonce, keyid) -> str:
    covered = " ".join(f'"{name}"' for name in components)
    return f'({covered});created={created};nonce={_sf_string(nonce)};keyid={_sf_string(keyid)};tag="gnap"'


def signature_base(components, method, url, headers, serialised) -> str:
    lines = []
    for component in components:
        if component == "@method":
            value = method.upper()
        elif component == "@target-uri":
            value = url
        else:
            if component not in headers:
                raise TypeError(f'Cannot sign "{component}": the request has no such header')
            value = headers[component].strip()
        if "\r" in value or "\n" in value:
            raise TypeError(f'Cannot sign "{component}": the value contains a line break')
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {serialised}')
    return "\n".join(lines)


def sign_request(key, method, url, headers=None, body=None, created=None, nonce=None, label="sig1") -> dict:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    href = url if parts.scheme else url
    # Keep the caller's URL when it is already absolute. Node's URL.href is what was signed.
    href = _href(url)
    lower = {name.lower(): value for name, value in (headers or {}).items()}
    components = ["@method", "@target-uri"]
    added = {}
    if body is not None and len(body) > 0:
        added["content-digest"] = content_digest(body)
        lower["content-digest"] = added["content-digest"]
        components.append("content-digest")
    if "authorization" in lower:
        components.append("authorization")
    if created is None:
        created = int(__import__("time").time())
    if nonce is None:
        from .codec import b64url
        nonce = b64url(os.urandom(16))
    params = signature_params(components, created, nonce, key.kid)
    base = signature_base(components, method, href, lower, params)
    signature = sign_raw(key, base.encode("utf-8"))
    added["signature-input"] = f"{label}={params}"
    added["signature"] = f"{label}=:{b64std(signature)}:"
    return added


def _href(url: str) -> str:
    """Absolute URL in the form Node's URL.href produces for http(s)."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return url
    host = parts.hostname
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    netloc = host
    if parts.port and not ((parts.scheme == "http" and parts.port == 80) or (parts.scheme == "https" and parts.port == 443)):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))
