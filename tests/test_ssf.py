# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from gnap_caep_risc import EVENT, SignalsReceiver, subject_of, verify_compact_jws
from gnap_caep_risc.codec import b64url
from gnap_caep_risc.ssf.session import TrackedSession

PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _unsigned(number):
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _jwk(private, kid):
    numbers = private.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": b64url(_unsigned(numbers.n)),
        "e": b64url(_unsigned(numbers.e)),
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
    }


JWK = _jwk(PRIVATE, "k1")


def jws(payload, key=PRIVATE, header=None):
    header = {"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"} if header is None else header
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url(sig)}"


class _State:
    def __init__(self):
        self.queue = {}
        self.acked = []
        self.errs = {}
        self.streams = []
        self.created = 0
        self.authorization = ""
        self.base = ""


def start_transmitter():
    state = _State()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _read(self):
            length = int(self.headers.get("content-length") or 0)
            return self.rfile.read(length).decode() if length else ""

        def _out(self, status, body=None):
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def _handle(self):
            text = self._read()
            state.authorization = self.headers.get("authorization") or ""
            path = self.path.split("?", 1)[0]
            if state.authorization != "GNAP app-token" and path != "/.well-known/ssf-configuration" and not path.startswith("/jwks"):
                self._out(401, {"error": "invalid_token"})
                return
            if path == "/.well-known/ssf-configuration":
                self._out(200, {
                    "issuer": state.base, "jwks_uri": f"{state.base}/jwks",
                    "configuration_endpoint": f"{state.base}/ssf/stream",
                    "verification_endpoint": f"{state.base}/ssf/verify",
                    "delivery_methods_supported": ["urn:ietf:rfc:8936"],
                })
                return
            if path == "/jwks":
                self._out(200, {"keys": [JWK]})
                return
            if path == "/ssf/stream" and self.command == "GET":
                self._out(200, state.streams)
                return
            if path == "/ssf/stream" and self.command == "POST":
                body = json.loads(text)
                state.created += 1
                stream = {
                    "stream_id": f"s{state.created}", "iss": state.base, "aud": "my-app",
                    "delivery": {"method": body["delivery"]["method"], "endpoint_url": f"{state.base}/ssf/poll/s{state.created}"},
                    "events_requested": body["events_requested"], "events_delivered": body["events_requested"],
                }
                state.streams.append(stream)
                self._out(201, stream)
                return
            if path == "/ssf/verify":
                self._out(204)
                return
            if path.startswith("/ssf/poll/"):
                body = json.loads(text or "{}")
                for jti in body.get("ack") or []:
                    state.acked.append(jti)
                    state.queue.pop(jti, None)
                state.errs.update(body.get("setErrs") or {})
                for jti in (body.get("setErrs") or {}):
                    state.queue.pop(jti, None)
                self._out(200, {"sets": dict(state.queue), "moreAvailable": False})
                return
            self._out(404, {"error": "not_found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    state.base = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


def deliver(state, type, sub_id, extra=None, key=None, aud=None, iss=None):
    jti = str(uuid.uuid4())
    state.queue[jti] = jws({
        "iss": iss or state.base, "aud": aud or "my-app", "jti": jti, "iat": 1,
        "sub_id": sub_id, "events": {type: {"event_timestamp": 1, **(extra or {})}},
    }, key or PRIVATE)
    return jti


def session(local_id, person, sid):
    return TrackedSession(local_id, f"urn:uuid:{person}", f"{person}@example.com", sid)


@pytest.fixture(scope="module")
def stub():
    server, state = start_transmitter()
    yield state
    server.shutdown()


def test_verifies_a_set_and_refuses_another_key():
    assert verify_compact_jws(jws({"a": 1}), [JWK])["payload"] == {"a": 1}
    with pytest.raises(Exception, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, OTHER), [JWK])
    with pytest.raises(Exception, match="kid nope"):
        verify_compact_jws(jws({"a": 1}, PRIVATE, {"alg": "RS256", "kid": "nope"}), [JWK])
    with pytest.raises(Exception, match="does not verify"):
        verify_compact_jws(jws({"a": 1}, PRIVATE, {"alg": "none"}), [JWK])


def test_reads_subject_forms():
    assert EVENT.session_revoked == "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    assert EVENT.credential_compromise == "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
    assert subject_of({
        "format": "complex",
        "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
        "session": {"format": "opaque", "id": "S1"},
    }, "https://i") == {"person": "urn:uuid:a", "idp_session": "S1"}
    assert subject_of({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i") == {}
    assert subject_of({"format": "email", "email": "A@x.com"}, "https://i") == {"email": "A@x.com"}


def test_polls_with_the_gnap_token_and_acknowledges(stub):
    ended = []
    seen = []
    signed = []

    class Quiet:
        def info(self, *args):
            return

        def warn(self, *args):
            return

        def error(self, *args):
            return

    receiver = SignalsReceiver(
        stub.base,
        lambda ids, event: ended.append(ids),
        headers=lambda request: signed.append(request) or {"authorization": "GNAP app-token"},
        poll_interval_ms=60_000,
        log=Quiet(),
    )
    receiver.on("*", lambda event: seen.append(event))
    receiver.start()
    receiver.stop()
    assert stub.created == 1
    assert stub.authorization == "GNAP app-token"
    assert receiver.stream["stream_id"] == "s1"
    created = next(request for request in signed if request["method"] == "POST" and request["url"].endswith("/ssf/stream"))
    assert '"delivery"' in created["body"]

    receiver.track(session("L-a1", "alice", "IDP-A1"))
    receiver.track(session("L-a2", "alice", "IDP-A2"))
    receiver.track(session("L-b1", "bob", "IDP-B1"))
    revoked = deliver(stub, EVENT.session_revoked, {
        "format": "complex",
        "user": {"format": "iss_sub", "iss": stub.base, "sub": "urn:uuid:alice"},
        "session": {"format": "opaque", "id": "IDP-A1"},
    })
    deliver(stub, EVENT.credential_change, {"format": "iss_sub", "iss": stub.base, "sub": "urn:uuid:bob"}, {"credential_type": "password"})
    receiver.poll_once()
    assert ended == [["L-a1"]]
    assert len(seen) == 2
    assert seen[0].ended is True
    assert seen[1].type == EVENT.credential_change
    assert seen[1].ended is False
    poll = next(request for request in signed if "/ssf/poll/" in request["url"])
    assert poll["method"] == "POST"
    assert "maxEvents" in (poll.get("body") or "")
    receiver.poll_once()
    assert stub.acked == [revoked, *[item for item in stub.acked if item != revoked]]
    bad = deliver(stub, EVENT.account_disabled, {"format": "email", "email": "alice@example.com"}, key=OTHER)
    receiver.poll_once()
    receiver.poll_once()
    assert stub.errs[bad]["err"] == "invalid_key"
    receiver.verify("abc")
    receiver.stop()
