# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The client against a stub authorization server.

The stub verifies HTTP signatures and detached JWS by reconstructing the signed input. The finish
hash is hashed here, not with the library, except for the fixed interaction-hash vector.
"""

import json
import re
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from gnap_caep_risc import GnapClient, GnapError, create_self_signed_key_pair, interaction_hash, load_client_key, public_key_object
from gnap_caep_risc.codec import b64url, sha256
from gnap_caep_risc.keys import fingerprint256, public_key_from_jwk

ID_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _unsigned(number):
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _id_jwk():
    numbers = ID_KEY.public_key().public_numbers()
    return {
        "kty": "RSA", "n": b64url(_unsigned(numbers.n)), "e": b64url(_unsigned(numbers.e)),
        "kid": "id1", "alg": "RS256", "use": "sig",
    }


ID_JWK = _id_jwk()


def id_token(issuer, aud, sub):
    header = b64url(json.dumps({"alg": "RS256", "kid": "id1", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = b64url(json.dumps({
        "iss": issuer, "aud": aud, "sub": sub, "exp": now + 600, "iat": now,
        "email": f"{sub}@example.com", "sid": "sess-1", "name": "Ada",
    }, separators=(",", ":")).encode())
    sig = ID_KEY.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{b64url(sig)}"


def finish_hash(client_nonce, interact_ref, grant_endpoint):
    return b64url(sha256(f"{client_nonce}\nserver-nonce\n{interact_ref}\n{grant_endpoint}".encode()))


class _Behavior:
    def __init__(self):
        self.foreign = False
        self.bearer = False
        self.too_fast = False
        self.aud = "instance-1"
        self.sub = "user-1"
        self.iss_sub = None
        self.omit_token = False
        self.too_fast_sent = False


class _State:
    def __init__(self):
        self.base = ""
        self.seen = []
        self.public_key = None
        self.kid = ""
        self.behavior = _Behavior()
        self.client_fingerprint = ""


def _verify_httpsig(headers, method, raw, target, state):
    signature_input = headers.get("signature-input") or ""
    assert ";alg=" not in signature_input
    match = re.match(r"^sig1=\(([^)]*)\)(.*)$", signature_input)
    assert match, signature_input
    components = re.findall(r'"([^"]+)"', match.group(1))
    serialised = "(" + " ".join(f'"{item}"' for item in components) + ")" + match.group(2)
    assert 'tag="gnap"' in match.group(2)
    assert f'keyid="{state.kid}"' in match.group(2)
    lines = []
    for component in components:
        if component == "@method":
            value = method.upper()
        elif component == "@target-uri":
            value = target
        else:
            value = (headers.get(component) or "").strip()
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {serialised}')
    sig = re.match(r"^sig1=:([A-Za-z0-9+/=]*):$", headers.get("signature") or "")
    assert sig, "signature"
    signature = __import__("base64").b64decode(sig.group(1))
    size = len(signature) // 2
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size:], "big")
    state.public_key.verify(encode_dss_signature(r, s), "\n".join(lines).encode(), __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ec"]).ECDSA(hashes.SHA256()))
    if raw:
        digest = "sha-256=:" + __import__("base64").b64encode(sha256(raw.encode())).decode() + ":"
        assert headers.get("content-digest") == digest


def _verify_jwsd(headers, method, raw, target, state):
    parts = (headers.get("detached-jws") or "").split(".")
    assert len(parts) == 3
    header = json.loads(__import__("base64").urlsafe_b64decode(parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)))
    assert header["typ"] == "gnap-binding-jwsd"
    assert header["alg"] == "ES256"
    assert header["kid"] == state.kid
    assert header["htm"] == method.upper()
    assert header["uri"] == target
    token = re.sub(r"^GNAP ", "", headers.get("authorization") or "")
    if headers.get("authorization"):
        assert header["ath"] == b64url(sha256(token.encode("ascii")))
    else:
        assert "ath" not in header
    payload = b64url(sha256(raw.encode())) if raw else ""
    assert parts[1] == payload
    signature = __import__("base64").urlsafe_b64decode(parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4))
    size = len(signature) // 2
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size:], "big")
    state.public_key.verify(
        encode_dss_signature(r, s),
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ec"]).ECDSA(hashes.SHA256()),
    )


def _remember_key(body, state):
    doc = json.loads(body)
    client = doc.get("client")
    key = client.get("key") if isinstance(client, dict) else None
    jwk = (key or {}).get("jwk")
    if jwk:
        state.public_key = public_key_from_jwk(jwk)
        state.kid = jwk.get("kid") or ""


def start_server(client_cert_pem):
    state = _State()
    server_key = create_self_signed_key_pair("localhost", dns=["localhost"], ip=["127.0.0.1"])
    client_key = create_self_signed_key_pair("gnap-client")
    state.client_fingerprint = client_key.fingerprint256
    cert_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".crt")
    key_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".key")
    cert_file.write(server_key.certificate_pem)
    key_file.write(server_key.private_key_pem)
    cert_file.close()
    key_file.close()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _read(self):
            length = int(self.headers.get("content-length") or 0)
            return self.rfile.read(length).decode() if length else ""

        def _peer(self):
            sock = self.connection
            if not isinstance(sock, ssl.SSLSocket):
                return ""
            try:
                der = sock.getpeercert(binary_form=True)
            except Exception:
                return ""
            if not der:
                return ""
            return fingerprint256(x509.load_der_x509_certificate(der))

        def _out(self, status, body=None):
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self):
            self._handle()

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_DELETE(self):
            self._handle()

        def _handle(self):
            raw = self._read()
            path = self.path.split("?", 1)[0]
            target = f"{state.base}{path}"
            headers = {name.lower(): value for name, value in self.headers.items()}
            state.seen.append({
                "method": self.command,
                "url": path,
                "body": raw,
                "authorization": headers.get("authorization", ""),
                "signature": headers.get("signature", ""),
                "detached": headers.get("detached-jws", ""),
                "cert": self._peer(),
            })
            try:
                if self.command == "OPTIONS" and path == "/gnap":
                    self._out(200, {
                        "grant_request_endpoint": f"{state.base}/gnap",
                        "key_proofs_supported": ["httpsig", "jwsd", "mtls"],
                        "interaction_start_modes_supported": ["redirect"],
                        "interaction_finish_methods_supported": ["redirect", "push"],
                        "sub_id_formats_supported": ["iss_sub", "opaque"],
                        "assertion_formats_supported": ["id_token"],
                    })
                    return
                if path == "/.well-known/openid-configuration":
                    self._out(200, {"issuer": state.base, "jwks_uri": f"{state.base}/jwks"})
                    return
                if path == "/jwks":
                    self._out(200, {"keys": [ID_JWK]})
                    return
                if raw and path == "/gnap":
                    _remember_key(raw, state)
                if headers.get("signature"):
                    _verify_httpsig(headers, self.command, raw, target, state)
                if headers.get("detached-jws"):
                    _verify_jwsd(headers, self.command, raw, target, state)
                behavior = state.behavior
                if path == "/gnap" and self.command == "POST":
                    cont = "https://evil.example/continue" if behavior.foreign else f"{state.base}/continue"
                    self._out(200, {
                        "instance_id": "instance-1",
                        "interact": {"redirect": f"{state.base}/interact/1", "finish": "server-nonce"},
                        "continue": {"uri": cont, "wait": 0, "access_token": {"value": "cont-token"}},
                    })
                    return
                if path == "/continue" and self.command == "POST":
                    assert headers.get("authorization") == "GNAP cont-token"
                    if behavior.too_fast and not behavior.too_fast_sent:
                        behavior.too_fast_sent = True
                        self._out(400, {"error": "too_fast", "continue": {"uri": f"{state.base}/continue", "wait": 0, "access_token": {"value": "cont-token"}}})
                        return
                    if behavior.omit_token:
                        self._out(200, {"instance_id": "instance-1"})
                        return
                    token = id_token(state.base, behavior.aud, behavior.sub)
                    self._out(200, {
                        "instance_id": "instance-1",
                        "access_token": {
                            "value": "access-1",
                            "access": ["ssf.read", "ssf.manage"],
                            "expires_in": 3600,
                            **({"flags": ["bearer"]} if behavior.bearer else {}),
                            "manage": {"uri": f"{state.base}/token/grant-9", "access_token": {"value": "manage-1"}},
                        },
                        "continue": {"uri": f"{state.base}/continue/grant-9", "access_token": {"value": "cont-next"}},
                        "subject": {
                            "sub_ids": [{"format": "iss_sub", "iss": state.base, "sub": behavior.iss_sub or behavior.sub}],
                            "assertions": [{"format": "id_token", "value": token}],
                        },
                    })
                    return
                if path == "/token/grant-9" and self.command == "POST":
                    assert headers.get("authorization") == "GNAP manage-1"
                    self._out(200, {"access_token": {"value": "access-2", "expires_in": 3600, "manage": {"uri": f"{state.base}/token/grant-9", "access_token": {"value": "manage-2"}}}})
                    return
                if self.command == "DELETE":
                    self._out(204)
                    return
                self._out(404, {"error": "not_found"})
            except Exception as err:
                self._out(401, {"error": "invalid_client", "error_description": str(err)})

    class Secure(ThreadingHTTPServer):
        def get_request(self):
            sock, addr = super().get_request()
            try:
                return context.wrap_socket(sock, server_side=True), addr
            except Exception:
                sock.close()
                raise

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file.name, key_file.name)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(cadata=client_key.certificate_pem)
    server = Secure(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    state.base = f"https://127.0.0.1:{server.server_address[1]}"
    state.server_cert = server_key.certificate_pem
    state.client_key = client_key
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


@pytest.fixture(scope="module")
def stub():
    server, state = start_server("")
    yield state
    server.shutdown()


def _client(state, proof, extra=None):
    body = {
        "grantEndpoint": f"{state.base}/gnap",
        "idTokenIssuer": state.base,
        "application": "gnap-caep-risc-demo",
        "display": {"name": "GNAP CAEP RISC demo", "uri": "http://127.0.0.1:3000/"},
        "access": ["ssf.read", "ssf.manage"],
        "subIdFormats": ["iss_sub", "account", "opaque"],
        "assertionFormats": ["id_token"],
        "keyProof": proof,
        "privateKey": state.client_key.private_key_pem,
        "certificate": state.client_key.certificate_pem,
        "finishUri": "http://127.0.0.1:3000/callback",
        "finishMethod": "redirect",
        "tlsCa": state.server_cert,
    }
    body.update(extra or {})
    return GnapClient.create(GnapClient.resolve(body, "."))


def _started(gnap, state):
    result = gnap.request_grant()
    assert result.pending is not None
    request = json.loads([call["body"] for call in state.seen if call["method"] == "POST" and call["url"] == "/gnap"][-1])
    return result, request


def test_interaction_hash_vector():
    assert interaction_hash("abc", "def", "xyz", "https://as.example/gnap") == "2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0"


def test_refuses_front_channel_foreign_and_a_hash_that_is_not_ours(stub):
    gnap = _client(stub, "httpsig")
    stub.behavior.foreign = True
    with pytest.raises(GnapError, match="not on the grant endpoint"):
        gnap.request_grant()
    assert not [call for call in stub.seen if call["url"] == "/continue"]
    stub.behavior.foreign = False
    stub.seen = []
    presenting = _client(stub, "httpsig")
    result, request = _started(presenting, stub)
    assert request["client"]["key"]["proof"] == "httpsig"
    assert "class_id" not in request["client"]
    assert request["subject"]["sub_id_formats"] == ["iss_sub", "opaque"]
    assert len(stub.seen[-1]["signature"]) > 0
    digest = finish_hash(request["interact"]["finish"]["nonce"], "ref-1", f"{stub.base}/gnap")
    with pytest.raises(GnapError, match="tokens through the browser") as caught:
        presenting.finish_redirect(f"hash={digest}&interact_ref=ref-1&access_token=no", [result.pending.id])
    assert "front" not in str(caught.value)
    with pytest.raises(GnapError, match="this browser"):
        presenting.finish_redirect(f"hash={digest}&interact_ref=ref-1", ["somebody-else"])
    assert not [call for call in stub.seen if call["url"] == "/continue"]
    with pytest.raises(GnapError, match="this browser"):
        presenting.finish_redirect(f"hash=nope&interact_ref=ref-1", [result.pending.id])


def test_finishes_a_redirect_checks_the_id_token_and_rotates(stub):
    stub.seen = []
    stub.behavior.too_fast_sent = False
    stub.behavior.too_fast = True
    stub.behavior.bearer = False
    stub.behavior.aud = "instance-1"
    stub.behavior.sub = "user-1"
    stub.behavior.iss_sub = None
    gnap = _client(stub, "httpsig")
    result, request = _started(gnap, stub)
    digest = finish_hash(request["interact"]["finish"]["nonce"], "ref-1", f"{stub.base}/gnap")
    done = gnap.finish_redirect({"hash": digest, "interact_ref": "ref-1"}, [result.pending.id])
    assert done.grant.access_token == "access-1"
    assert done.grant.bearer is False
    assert done.grant.subject.sub == "user-1"
    assert done.grant.subject.email == "user-1@example.com"
    assert done.grant.subject.sid == "sess-1"
    assert done.grant.subject.assertion_verified is True
    assert done.grant.grant_id == "grant-9"
    assert stub.behavior.too_fast_sent is True
    again = gnap.request_grant()
    assert again.pending is not None
    second = json.loads([call["body"] for call in stub.seen if call["url"] == "/gnap" and call["method"] == "POST"][-1])
    assert second["client"] == "instance-1"
    rotated = gnap.rotate(done.grant)
    assert rotated.access_token == "access-2"
    assert rotated.subject.sub == "user-1"
    assert rotated.continuation.uri == done.grant.continuation.uri
    gnap.revoke(rotated)
    assert stub.seen[-1]["method"] == "DELETE"
    with pytest.raises(GnapError, match="already used"):
        gnap.finish_redirect({"hash": digest, "interact_ref": "ref-1"}, [result.pending.id])


def test_proves_the_key_with_detached_jws_and_mutual_tls(stub):
    stub.seen = []
    stub.behavior.too_fast = False
    jwsd = _client(stub, "jwsd")
    first_result, first = _started(jwsd, stub)
    assert first["client"]["key"]["proof"] == "jwsd"
    digest = finish_hash(first["interact"]["finish"]["nonce"], "ref-j", f"{stub.base}/gnap")
    done = jwsd.finish_redirect(f"?hash={digest}&interact_ref=ref-j", [first_result.pending.id])
    assert done.grant.subject.name == "Ada"
    assert any(call["url"] == "/continue" and "." in call["detached"] for call in stub.seen)
    assert next(call for call in stub.seen if call["url"] == "/continue")["signature"] == ""

    stub.seen = []
    mtls = _client(stub, "mtls")
    second_result, second = _started(mtls, stub)
    assert second["client"]["key"]["proof"] == "mtls"
    assert next(call for call in stub.seen if call["url"] == "/gnap")["cert"] == stub.client_fingerprint
    assert next(call for call in stub.seen if call["url"] == "/gnap")["signature"] == ""
    assert next(call for call in stub.seen if call["url"] == "/gnap")["detached"] == ""
    digest2 = finish_hash(second["interact"]["finish"]["nonce"], "ref-m", f"{stub.base}/gnap")
    finished = mtls.finish_push({"hash": digest2, "interact_ref": "ref-m"})
    assert finished.grant.access_token == "access-1"
    answer = mtls.call(finished.grant, f"{stub.base}/jwks")
    assert answer.status == 200
    assert re.match(r"^GNAP access-1$", stub.seen[-1]["authorization"])
    assert second_result.pending.id


def test_refuses_bearer_bad_audience_and_a_subject_that_does_not_match(stub):
    stub.behavior.bearer = True
    gnap = _client(stub, "httpsig")
    result, request = _started(gnap, stub)
    digest = finish_hash(request["interact"]["finish"]["nonce"], "ref-b", f"{stub.base}/gnap")
    with pytest.raises(GnapError, match="bearer") as caught:
        gnap.finish_redirect({"hash": digest, "interact_ref": "ref-b"}, [result.pending.id])
    assert caught.value.code == "validation"
    stub.behavior.bearer = False
    stub.behavior.aud = "someone-else"
    audience = _client(stub, "httpsig")
    next_result, next_request = _started(audience, stub)
    digest2 = finish_hash(next_request["interact"]["finish"]["nonce"], "ref-a", f"{stub.base}/gnap")
    with pytest.raises(GnapError, match="id_token is for"):
        audience.finish_redirect({"hash": digest2, "interact_ref": "ref-a"}, [next_result.pending.id])
    stub.behavior.aud = "gnap-caep-risc-demo"
    stub.behavior.iss_sub = "other-user"
    stub.behavior.sub = "user-1"
    third_result, third = _started(gnap, stub)
    digest3 = finish_hash(third["interact"]["finish"]["nonce"], "ref-s", f"{stub.base}/gnap")
    with pytest.raises(GnapError, match="somebody other"):
        gnap.finish_redirect({"hash": digest3, "interact_ref": "ref-s"}, [third_result.pending.id])
    stub.behavior.iss_sub = None
    stub.behavior.aud = "instance-1"


def test_accepts_the_application_identifier_as_the_id_token_audience(stub):
    stub.behavior.aud = "gnap-caep-risc-demo"
    stub.behavior.sub = "user-2"
    stub.behavior.iss_sub = None
    stub.behavior.bearer = False
    stub.behavior.too_fast = False
    gnap = _client(stub, "httpsig")
    result, request = _started(gnap, stub)
    digest = finish_hash(request["interact"]["finish"]["nonce"], "ref-app", f"{stub.base}/gnap")
    done = gnap.finish_redirect({"hash": digest, "interact_ref": "ref-app"}, [result.pending.id])
    assert done.grant.subject.sub == "user-2"
    stub.behavior.aud = "instance-1"
    done.grant.expires_at = time.time() * 1000 + 10_000
    fresh = gnap.ensure_fresh(done.grant)
    assert fresh.access_token == "access-2"
    fresh.expires_at = time.time() * 1000 + 3_600_000
    held = gnap.ensure_fresh(fresh)
    assert held.access_token == "access-2"


def test_certificate_chain_puts_the_leaf_in_the_key_and_the_chain_on_tls():
    leaf = create_self_signed_key_pair("leaf.example")
    issuer = create_self_signed_key_pair("issuer.example")
    chain = f"{leaf.certificate_pem.strip()}\n{issuer.certificate_pem.strip()}\n"
    key = load_client_key(leaf.private_key_pem, chain, "mtls")
    published = public_key_object(key)
    assert len(re.findall("BEGIN CERTIFICATE", published["cert"])) == 1
    loaded = x509.load_pem_x509_certificate(published["cert"].encode())
    assert fingerprint256(loaded) == leaf.fingerprint256
    gnap = GnapClient.create(GnapClient.resolve({
        "grantEndpoint": "https://as.example/gnap",
        "application": "chain-demo",
        "keyProof": "mtls",
        "privateKey": leaf.private_key_pem,
        "certificate": chain,
        "finishUri": "http://127.0.0.1:9/callback",
    }, "."))
    assert len(re.findall("BEGIN CERTIFICATE", gnap.tls()["cert"])) == 2
