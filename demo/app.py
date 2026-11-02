# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""A small GNAP sign-in demo. The private key stays in this process. Tokens stay off the browser.

GET  /healthz      200 and the body ok. This does not read the client key.
GET  /live-status  JSON: signedIn, subject, receiver, and accepted events. No tokens.
GET  /             a page with a sign-in control, or the signed-in page
GET  /login        starts a grant and redirects the browser
GET  /callback     finishes the redirect
POST /logout       signs this browser out of this application
POST /gnap/push    a push finish

PORT is the bind port (default 3000). A loopback finish URI and display URI follow that port.
PUBLIC_URL or --public-url replaces the origin and keeps the path. pollIntervalMs is the Shared
Signals poll interval in milliseconds.
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "scripts"))

from gnap_caep_risc import GnapClient, GnapError, MemorySessionIndex, SignalsReceiver, tracked_from_person  # noqa: E402
from redirects import redirects_for  # noqa: E402

CONFIG = Path(os.environ.get("GNAP_CONFIG") or (HERE / "gnap.json"))
SECRET = os.environ.get("SESSION_SECRET", "").encode() or secrets.token_bytes(32)
PUBLIC = HERE / "public"


def _args(argv):
    public = os.environ.get("PUBLIC_URL") or ""
    given = bool(public)
    index = 0
    while index < len(argv):
        if argv[index] == "--public-url":
            index += 1
            public = argv[index] if index < len(argv) else ""
            given = True
        index += 1
    return public.rstrip("/"), given


PUBLIC_URL, PUBLIC_GIVEN = _args(sys.argv[1:])
PORT = int(os.environ.get("PORT") or 3000)

GNAP = None
GNAP_ERROR = None
SESSION = {}
RECEIVER = None
RECEIVER_STATE = ""
LATEST = None
EVENTS = []


class _SessionIndex(MemorySessionIndex):
    """An ending event names an IdP session. A sign-in that recorded none still ends."""

    def by_idp_session(self, idp_session):
        found = super().by_idp_session(idp_session)
        if found:
            return found
        return self._find(lambda session: not session.idp_session)


def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    import base64
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def seal(payload) -> str:
    raw = _b64(json.dumps(payload, separators=(",", ":")).encode())
    mac = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def unseal(token):
    if not token or "." not in token:
        return None
    raw, mac = token.rsplit(".", 1)
    expected = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return None
    try:
        return json.loads(_unb64(raw))
    except Exception:
        return None


def _cookie(header, name):
    for part in (header or "").split(";"):
        item = part.strip()
        if item.startswith(name + "="):
            return item[len(name) + 1:]
    return ""


def read_raw():
    raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    display = raw.get("display") if isinstance(raw.get("display"), dict) else None
    moved = redirects_for(
        raw.get("finishUri") if isinstance(raw.get("finishUri"), str) else "",
        display.get("uri") if display and isinstance(display.get("uri"), str) else "",
        PUBLIC_URL or "http://localhost:3000",
        PUBLIC_GIVEN,
        PORT,
    )
    if moved.get("finishUri"):
        raw["finishUri"] = moved["finishUri"]
    if display and moved.get("displayUri"):
        display["uri"] = moved["displayUri"]
        raw["display"] = display
    return raw


def client():
    global GNAP, GNAP_ERROR
    if GNAP is None:
        try:
            GNAP = GnapClient.create(GnapClient.resolve(read_raw(), str(CONFIG.parent)))
            GNAP_ERROR = None
        except Exception as err:
            GNAP_ERROR = f"{err.code}: {err}" if isinstance(err, GnapError) else str(err)
            raise
    return GNAP


def try_client():
    try:
        return client()
    except Exception:
        return None


def _signals_wanted():
    try:
        raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return None
    if raw.get("signals") is False:
        return None
    ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else None
    if not ssf or not ssf.get("transmitter"):
        return None
    return ssf


def _remember_event(event):
    EVENTS.append({"type": event.type, "jti": event.jti})


def _subject_label(person):
    if person is None:
        return None
    for name in ("preferred_username", "email", "name", "uid", "sub"):
        value = getattr(person, name, None)
        if isinstance(value, str) and value:
            return value
    return None


def _watch(local_id, grant, person):
    global RECEIVER, RECEIVER_STATE, LATEST
    LATEST = grant
    wanted = _signals_wanted()
    if not wanted:
        if not RECEIVER_STATE:
            RECEIVER_STATE = "not configured (no ssf block in the configuration file)"
        return
    if RECEIVER is None:
        interval = wanted.get("pollIntervalMs") or 5000

        def headers(request):
            if LATEST is None:
                return {}
            return client().authorization_headers(LATEST, request["method"], request["url"], request.get("body"))

        def ended(ids, event):
            for one in ids:
                SESSION.pop(one, None)

        receiver = SignalsReceiver(
            wanted["transmitter"],
            ended,
            tls=client().tls(),
            headers=headers,
            description=f"gnap-caep-risc demo ({client().config.application})",
            poll_interval_ms=interval,
            session_index=_SessionIndex(),
        )
        receiver.on("*", _remember_event)
        RECEIVER = receiver
        try:
            receiver.start()
            stream = receiver.stream or {}
            RECEIVER_STATE = f"polling stream {stream.get('stream_id')} at {wanted['transmitter']}"
        except Exception as err:
            print(f"ssf: not started: {err}")
            RECEIVER = None
            RECEIVER_STATE = f"not running: {err}"
    if RECEIVER is None or person is None or not local_id:
        return
    if not getattr(person, "sid", None):
        print("ssf: the sign-in has no IdP session id; an ending event still clears this local session")
    RECEIVER.track(tracked_from_person(local_id, person, grant.expires_at))


def _page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"""


def _esc(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


class Demo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def _read(self):
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status, body, headers=None, code=None):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        extra = headers or {}
        if "content-type" not in {name.lower() for name in extra}:
            self.send_header("content-type", "text/html; charset=utf-8")
        for name, value in extra.items():
            if isinstance(value, list):
                for item in value:
                    self.send_header(name, item)
            else:
                self.send_header(name, value)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _static(self, name, content_type):
        path = PUBLIC / name
        if not path.is_file():
            self._send(404, _page("Not found", "<h1>Not found</h1>"))
            return
        self._send(200, path.read_bytes(), {"content-type": content_type, "cache-control": "max-age=300"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        try:
            if path == "/healthz" and method == "GET":
                self._send(200, "ok", {"content-type": "text/plain"})
                return
            if path == "/live-status" and method == "GET":
                self._live_status()
                return
            if path == "/styles.css" and method == "GET":
                self._static("styles.css", "text/css; charset=utf-8")
                return
            if path == "/app.js" and method == "GET":
                self._static("app.js", "text/javascript; charset=utf-8")
                return
            if path == "/" and method == "GET":
                self._home()
                return
            if path == "/login" and method == "GET":
                self._login()
                return
            if path == "/callback" and method == "GET":
                self._callback(query)
                return
            if path == "/logout" and method == "POST":
                self._logout()
                return
            if path == "/gnap/push" and method == "POST":
                self._push()
                return
            self._send(404, _page("Not found", "<h1>Not found</h1>"))
        except Exception as err:
            print(err)
            self._send(500, _page("Error", f"<h1>Something went wrong</h1><p>{_esc(err)}</p><p><a href=\"/\">Home</a></p>"))

    def _session(self):
        token = _cookie(self.headers.get("cookie"), "gsid")
        opened = unseal(token)
        if not isinstance(opened, dict):
            return None
        return SESSION.get(opened.get("id"))

    def _live_status(self):
        session = self._session()
        person = session["person"] if session else None
        body = {
            "signedIn": bool(session),
            "subject": _subject_label(person),
            "receiver": RECEIVER_STATE,
            "events": [{"type": item.get("type"), "jti": item.get("jti")} for item in list(EVENTS)],
        }
        self._send(200, json.dumps(body), {"content-type": "application/json", "cache-control": "no-store"})

    def _home(self):
        gnap = try_client()
        session = self._session()
        if session:
            person = session["person"]
            who = _esc(getattr(person, "email", None) or getattr(person, "name", None) or person.sub)
            body = f"<h1>Signed in</h1><p>{who}</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>"
            self._send(200, _page("Signed in", body))
            return
        problem = "" if gnap else f"<p>The GNAP client is not configured yet: {_esc(GNAP_ERROR or 'the key could not be read')}. Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>"
        link = '<p><a class="button" href="/login">Sign in with GNAP</a></p>' if gnap else ""
        self._send(200, _page("GNAP demo", f"<h1>GNAP CAEP RISC demo</h1>{problem}{link}"))

    def _login(self):
        try:
            started = client().request_grant()
        except Exception as err:
            self._send(400, _page("Sign-in failed", f"<h1>Sign-in failed</h1><p>{_esc(err)}</p><p><a href=\"/\">Start again</a></p>"))
            return
        if started.grant is not None:
            self._place(started.grant)
            return
        pending = seal({"ids": [started.pending.id]})
        secure = ""
        finish = getattr(client().config, "finish_uri", "") or ""
        if finish.startswith("https:"):
            secure = "; Secure"
        self._send(302, "", {
            "location": started.redirect_url,
            "set-cookie": f"gpending={pending}; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax{secure}",
            "cache-control": "no-store",
        })

    def _callback(self, query):
        pending = unseal(_cookie(self.headers.get("cookie"), "gpending"))
        ids = pending.get("ids") if isinstance(pending, dict) else []
        flat = {key: values[0] for key, values in query.items() if values}
        clear = "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax"
        try:
            done = client().finish_redirect(flat, ids or [])
            if done.grant.subject is None:
                raise GnapError("validation", "the grant has no subject")
            self._place(done.grant, clear)
        except Exception as err:
            print(f"sign-in refused: {err}")
            self._send(400, _page("Sign-in failed", f"<h1>Sign-in failed</h1><p>{_esc(err)}</p><p><a href=\"/\">Start again</a></p>"), {"set-cookie": clear})

    def _place(self, grant, extra=None):
        local = secrets.token_urlsafe(12)
        SESSION[local] = {"person": grant.subject, "grant": grant}
        if grant.subject is not None:
            _watch(local, grant, grant.subject)
        cookies = [f"gsid={seal({'id': local})}; Path=/; HttpOnly; SameSite=Lax"]
        if extra:
            cookies.append(extra)
        self._send(303, "", {"location": "/", "set-cookie": cookies, "cache-control": "no-store"})

    def _logout(self):
        token = _cookie(self.headers.get("cookie"), "gsid")
        opened = unseal(token)
        if isinstance(opened, dict):
            local = opened.get("id")
            session = SESSION.pop(local, None)
            if session and RECEIVER is not None and local:
                try:
                    RECEIVER.untrack(local)
                except Exception:
                    pass
            if session:
                try:
                    client().revoke(session["grant"])
                except Exception as err:
                    print(f"revoke: {err}")
        self._send(303, "", {
            "location": "/",
            "set-cookie": "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            "cache-control": "no-store",
        })

    def _push(self):
        try:
            text = self._read().decode()
            done = client().finish_push(json.loads(text) if text else None)
            if done.grant.subject is not None:
                _watch(done.grant.grant_id or done.grant.subject.sub, done.grant, done.grant.subject)
            self._send(204, "", {"cache-control": "no-store"})
        except Exception as err:
            self._send(400, json.dumps({"error": str(err)}), {"content-type": "application/json"})


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Demo)
    print(f"gnap-caep-risc demo on port {PORT}, configuration {CONFIG}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if RECEIVER is not None:
            RECEIVER.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
