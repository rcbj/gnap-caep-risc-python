# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The back channel. TLS is verified unless the caller turns it off. Answers are capped at 2 MiB."""

import http.client
import ssl
import tempfile
from urllib.parse import urlsplit

from .errors import GnapError

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


class HttpAnswer:
    def __init__(self, status, content_type, body):
        self.status = status
        self.content_type = content_type
        self.body = body


def _context(tls) -> ssl.SSLContext:
    tls = tls or {}
    if tls.get("reject_unauthorized") is False:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
        ca = tls.get("ca")
        if ca:
            ctx.load_verify_locations(cadata=ca if isinstance(ca, str) else ca.decode("utf-8"))
    cert = tls.get("cert")
    key = tls.get("key")
    if cert and key:
        cert_file = tempfile.NamedTemporaryFile("w", delete=False, prefix="gnap-cert-", suffix=".pem")
        key_file = tempfile.NamedTemporaryFile("w", delete=False, prefix="gnap-key-", suffix=".pem")
        cert_file.write(cert)
        key_file.write(key)
        cert_file.close()
        key_file.close()
        ctx.load_cert_chain(cert_file.name, key_file.name)
    return ctx


def send(url, method="GET", headers=None, body=None, tls=None, code="protocol") -> HttpAnswer:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise GnapError(code, f"{url} is not an http(s) URL")
    payload = None if body is None else (body.encode("utf-8") if isinstance(body, str) else body)
    outgoing = {str(name): str(value) for name, value in (headers or {}).items()}
    if payload is not None:
        outgoing["content-length"] = str(len(payload))
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    try:
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, context=_context(tls), timeout=TIMEOUT_S)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT_S)
        conn.request(method, path, body=payload, headers=outgoing)
        response = conn.getresponse()
        chunks = []
        size = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                conn.close()
                raise GnapError(code, f"{url} answered more than {MAX_BYTES} bytes")
            chunks.append(chunk)
        raw = b"".join(chunks)
        answer = HttpAnswer(response.status, response.getheader("content-type") or "", raw.decode("utf-8", "replace"))
        conn.close()
        return answer
    except GnapError:
        raise
    except TimeoutError as err:
        raise GnapError(code, f"{url} did not answer within {TIMEOUT_S} s", cause=err) from err
    except Exception as err:
        if isinstance(err, ssl.SSLError) and "timed out" in str(err).lower():
            raise GnapError(code, f"{url} did not answer within {TIMEOUT_S} s", cause=err) from err
        message = getattr(err, "message", None) or str(err)
        raise GnapError(code, f"{url}: {message}", cause=err) from err
