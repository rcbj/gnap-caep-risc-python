# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Grant-server discovery is an OPTIONS on the grant endpoint. OpenID and SSF use RFC 8615 well-known URLs."""

import json
from urllib.parse import urlsplit

from .errors import GnapError
from .http import send


def _host(parts) -> str:
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port and not ((parts.scheme == "http" and parts.port == 80) or (parts.scheme == "https" and parts.port == 443)):
        return f"{host}:{parts.port}"
    return host


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{_host(parts)}"


def href_of(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    return f"{parts.scheme}://{_host(parts)}{path}" + (f"?{parts.query}" if parts.query else "")


def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")


def well_known_urls(issuer: str, suffix: str) -> list:
    parts = urlsplit(issuer)
    path = (parts.path or "").rstrip("/")
    origin = origin_of(issuer)
    inserted = f"{origin}/.well-known/{suffix}{path}"
    appended = f"{origin}{path}/.well-known/{suffix}"
    return [inserted] if inserted == appended else [inserted, appended]


def _list_of(value):
    if value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GnapError("discovery", "a grant-server metadata list is not an array of strings")
    return value


def validate_grant_server(raw, grant_endpoint: str) -> dict:
    if not isinstance(raw, dict):
        raise GnapError("discovery", "grant-server metadata must be a JSON object")
    endpoint = raw.get("grant_request_endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        raise GnapError("discovery", "grant-server metadata has no grant_request_endpoint")
    advertised = href_of(endpoint).rstrip("/")
    asked = href_of(grant_endpoint).rstrip("/")
    if advertised != asked:
        raise GnapError("discovery", f"the grant server says its endpoint is {endpoint}, not {grant_endpoint}")
    return {
        "grant_request_endpoint": endpoint,
        "interaction_start_modes_supported": _list_of(raw.get("interaction_start_modes_supported")),
        "interaction_finish_methods_supported": _list_of(raw.get("interaction_finish_methods_supported")),
        "key_proofs_supported": _list_of(raw.get("key_proofs_supported")),
        "sub_id_formats_supported": _list_of(raw.get("sub_id_formats_supported")),
        "assertion_formats_supported": _list_of(raw.get("assertion_formats_supported")),
    }


def discover_grant_server(grant_endpoint: str, tls) -> dict:
    answer = send(grant_endpoint, method="OPTIONS", headers={"accept": "application/json"}, tls=tls, code="discovery")
    try:
        parsed = json.loads(answer.body)
    except Exception as err:
        raise GnapError("discovery", f"{grant_endpoint} did not answer JSON grant-server metadata ({answer.status})", cause=err) from err
    if answer.status != 200:
        raise GnapError("discovery", f"{grant_endpoint} answered {answer.status} for discovery")
    return validate_grant_server(parsed, grant_endpoint)


def discover_open_id(issuer: str, tls) -> dict:
    urls = well_known_urls(issuer, "openid-configuration")
    last = GnapError("discovery", f"no OpenID Provider metadata at {' or '.join(urls)}")
    for url in urls:
        answer = send(url, headers={"accept": "application/json"}, tls=tls, code="discovery")
        if answer.status == 404 and url != urls[-1]:
            continue
        try:
            doc = json.loads(answer.body)
        except Exception:
            doc = None
        if answer.status != 200 or not isinstance(doc, dict) or not doc.get("jwks_uri"):
            last = GnapError("discovery", f"{url} answered {answer.status} without OpenID Provider metadata")
            continue
        got = doc.get("issuer")
        if isinstance(got, str) and got.rstrip("/") != issuer.rstrip("/"):
            raise GnapError("discovery", f"{url} says its issuer is {got}, not {issuer}")
        return {"issuer": got or issuer, "jwks_uri": doc["jwks_uri"]}
    raise last
