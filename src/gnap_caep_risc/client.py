# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""A server-side GNAP client (RFC 9635). The private key stays here. Tokens are key-bound.

The browser carries the interaction hash. A bearer flag is refused. A continue or manage URI on
another origin is refused before anything is sent there.
"""

import json
import os
import re
import time
from urllib.parse import parse_qsl, unquote, urlsplit

from .codec import b64url, dumps, is_number
from .config import read_config_file, resolve_config
from .discovery import discover_grant_server, discover_open_id, href_of, is_loopback, origin_of
from .errors import ErrorContinuation, GnapError
from .hashes import hash_equal, interaction_hash
from .http import send
from .httpsig import sign_request
from .jwsd import detached_jws
from .keys import public_key_object
from .subject import person_from

FRONT_CHANNEL = ("access_token", "id_token", "token", "value", "continue", "refresh_token")


class Continuation:
    def __init__(self, uri, access_token, wait=None):
        self.uri = uri
        self.access_token = access_token
        self.wait = wait


class Grant:
    def __init__(self, access_token, bearer, access, expires_in=None, expires_at=None, manage=None,
                 continuation=None, instance_id=None, subject=None, grant_id=None):
        self.access_token = access_token
        self.bearer = bearer
        self.access = access
        self.expires_in = expires_in
        self.expires_at = expires_at
        self.manage = manage
        self.continuation = continuation
        self.instance_id = instance_id
        self.subject = subject
        self.grant_id = grant_id


class PendingGrant:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class GrantResult:
    def __init__(self, redirect_url=None, pending=None, grant=None):
        self.redirect_url = redirect_url
        self.pending = pending
        self.grant = grant


class FinishedGrant:
    def __init__(self, grant, context=None):
        self.grant = grant
        self.context = context


class SecurityPosture:
    def __init__(self, key_proof, bound_tokens, finish_method):
        self.key_proof = key_proof
        self.bound_tokens = bound_tokens
        self.finish_method = finish_method
        self.interaction_hash = True
        self.registered_key = True


def _grant_id(uri):
    if not uri:
        return None
    try:
        parts = [part for part in urlsplit(uri).path.split("/") if part]
        return None if not parts else unquote(parts[-1])
    except Exception:
        return None


def _params(value):
    if hasattr(value, "get") and hasattr(value, "keys") and not isinstance(value, (str, bytes)):
        pairs = []
        for key in value.keys():
            raw = value.get(key)
            if isinstance(raw, (list, tuple)):
                for item in raw:
                    if isinstance(item, str):
                        pairs.append((key, item))
            elif isinstance(raw, str):
                pairs.append((key, raw))
        return pairs
    if isinstance(value, str):
        if re.match(r"^[a-z][a-z0-9+.-]*:", value, re.I) or value.startswith("/"):
            query = urlsplit(value).query
        else:
            query = value[1:] if value[:1] in "?#" else value
        return parse_qsl(query, keep_blank_values=True)
    raise GnapError("validation", "the finish redirect could not be read")


class GnapClient:
    def __init__(self, config):
        self.config = config
        self._metadata = None
        self._instance_id = None
        self._sub_id_formats = list(config.sub_id_formats)
        self._assertion_formats = list(config.assertion_formats)
        self._jwks = None
        self._pending = {}
        self._used = {}

    @classmethod
    def from_file(cls, path):
        return cls(read_config_file(path))

    @classmethod
    def create(cls, config):
        return cls(config)

    @staticmethod
    def resolve(raw, base_dir):
        return resolve_config(raw, base_dir)

    @property
    def key(self):
        return self.config.key

    @property
    def security(self):
        return SecurityPosture(self.config.key.proof, self.config.require_bound_tokens, self.config.finish_method)

    @property
    def instance_id(self):
        return self._instance_id

    def tls(self):
        out = {}
        if getattr(self.config, "tls_ca", None):
            out["ca"] = self.config.tls_ca
        key = self.config.key
        if key.proof == "mtls" and (key.tls_chain_pem or key.certificate_pem):
            out["cert"] = key.tls_chain_pem or key.certificate_pem
            out["key"] = key.private_pem()
        return out

    def discover(self):
        if self._metadata:
            return self._metadata
        metadata = discover_grant_server(self.config.grant_endpoint, self.tls())
        proofs = metadata.get("key_proofs_supported")
        if proofs and self.config.key.proof not in proofs:
            raise GnapError("discovery", f"the grant server does not accept the {self.config.key.proof} key proof")
        finishes = metadata.get("interaction_finish_methods_supported")
        if finishes and getattr(self.config, "finish_uri", None) and self.config.finish_method not in finishes:
            raise GnapError("discovery", f"the grant server does not accept a {self.config.finish_method} interaction finish")
        if metadata.get("sub_id_formats_supported"):
            self._sub_id_formats = [item for item in self._sub_id_formats if item in metadata["sub_id_formats_supported"]]
        if metadata.get("assertion_formats_supported"):
            self._assertion_formats = [item for item in self._assertion_formats if item in metadata["assertion_formats_supported"]]
        self._metadata = metadata
        return metadata

    def request_grant(self, access=None, user=None, expected_sub=None, context=None, subject=True):
        self.discover()
        rights = self.config.access if access is None else access
        if not isinstance(rights, list) or not rights:
            raise GnapError("config", "access is required")
        client_nonce = b64url(os.urandom(24))
        body = {"access_token": {"access": rights}, "client": self._client_member()}
        if getattr(self.config, "finish_uri", None):
            body["interact"] = {
                "start": self.config.interaction_start,
                "finish": {"method": self.config.finish_method, "uri": self.config.finish_uri, "nonce": client_nonce},
            }
        if subject is not False and (self._sub_id_formats or self._assertion_formats):
            subject_body = {}
            if self._sub_id_formats:
                subject_body["sub_id_formats"] = self._sub_id_formats
            if self._assertion_formats:
                subject_body["assertion_formats"] = self._assertion_formats
            body["subject"] = subject_body
        if user is not None:
            body["user"] = user
        answer = self._signed_json("POST", self.config.grant_endpoint, body=body)
        self._remember_instance(answer)
        if isinstance(answer, dict) and answer.get("interact"):
            return GrantResult(self._redirect(answer), self._remember_pending(answer, client_nonce, context, expected_sub))
        if self._has_token(answer):
            grant = self._grant_from(answer, {})
            self._expect(grant, expected_sub)
            return GrantResult(grant=grant)
        raise GnapError("protocol", "the grant response has neither an interaction nor an access token")

    def finish_redirect(self, query, allowed_ids):
        pairs = _params(query)
        names = {}
        for key, _value in pairs:
            names.setdefault(key, []).append(_value)
        injected = [name for name in FRONT_CHANNEL if name in names]
        if injected:
            raise GnapError("validation", f"the finish redirect carries {', '.join(injected)}; GNAP does not send tokens through the browser")
        for name, values in names.items():
            if len(values) > 1:
                raise GnapError("validation", f'the finish redirect repeats "{name}"')
        digest = names.get("hash", [None])[0]
        interact_ref = names.get("interact_ref", [None])[0]
        if not digest or not interact_ref:
            if names.get("error", [None])[0]:
                code = names["error"][0]
                raise GnapError("protocol", names.get("error_description", [None])[0] or code or "the interaction failed", gnap_error=code)
            raise GnapError("validation", "the finish redirect has no hash or interact_ref")
        pending = self._match(digest, interact_ref, allowed_ids)
        return self._finish(pending, interact_ref, digest)

    def finish_push(self, body):
        if not isinstance(body, dict):
            raise GnapError("validation", "a push finish is a JSON object")
        if not isinstance(body.get("hash"), str) or not isinstance(body.get("interact_ref"), str):
            if isinstance(body.get("error"), str):
                raise GnapError("protocol", body["error"], gnap_error=body["error"])
            raise GnapError("validation", "a push finish needs hash and interact_ref")
        pending = self._match(body["hash"], body["interact_ref"])
        return self._finish(pending, body["interact_ref"], body["hash"])

    def authorization_headers(self, grant, method, url, body=None, headers=None):
        return self._proof_headers(method, url, body, grant.access_token, headers)

    def call(self, grant, url, method="GET", headers=None, body=None):
        proof = self.authorization_headers(grant, method, url, body, headers)
        merged = {**(headers or {}), **proof}
        return send(url, method=method, headers=merged, body=body, tls=self.tls(), code="protocol")

    def rotate(self, grant):
        if not grant.manage:
            raise GnapError("protocol", "this access token has no manage URI")
        self._check_same_origin(grant.manage.uri, "manage.uri")
        answer = self._signed_json("POST", grant.manage.uri, token=grant.manage.access_token)
        if not self._has_token(answer):
            raise GnapError("protocol", "the rotation returned no access token")
        nxt = self._grant_from(answer, {"previous": grant})
        if not grant.bearer and nxt.bearer:
            raise GnapError("validation", "rotating a key-bound token returned a bearer token")
        return nxt

    def revoke(self, grant):
        if not grant.continuation:
            raise GnapError("protocol", "this grant has no continuation, so it cannot be revoked")
        self._check_same_origin(grant.continuation.uri, "continue.uri")
        self._signed_json("DELETE", grant.continuation.uri, token=grant.continuation.access_token)

    def ensure_fresh(self, grant, now=None):
        now = time.time() * 1000 if now is None else now
        if grant.expires_at is None or grant.expires_at - now > 60_000:
            return grant
        return self.rotate(grant)

    def _client_member(self):
        if self.config.use_instance_id and self._instance_id:
            return self._instance_id
        member = {"key": public_key_object(self.config.key)}
        if getattr(self.config, "display", None):
            member["display"] = self.config.display
        if getattr(self.config, "class_id", None):
            member["class_id"] = self.config.class_id
        return member

    def _remember_instance(self, answer):
        if not self.config.use_instance_id or not isinstance(answer, dict):
            return
        identifier = answer.get("instance_id")
        if isinstance(identifier, str) and identifier:
            self._instance_id = identifier

    def _redirect(self, answer):
        redirect = (answer.get("interact") or {}).get("redirect")
        if not isinstance(redirect, str):
            raise GnapError("protocol", "the interaction is not a redirect")
        try:
            parts = urlsplit(redirect)
            if not parts.scheme or not parts.hostname:
                raise ValueError(redirect)
        except Exception:
            raise GnapError("protocol", f"interact.redirect is not a URL: {redirect}") from None
        if parts.scheme != "https" and not (parts.scheme == "http" and (self.config.allow_insecure or is_loopback(redirect))):
            raise GnapError("validation", f"interact.redirect must use https: {redirect}")
        return redirect

    def _remember_pending(self, answer, client_nonce, context, expected_sub):
        finish = (answer.get("interact") or {}).get("finish")
        if not isinstance(finish, str) or not finish:
            raise GnapError("protocol", "the grant response has no interaction finish nonce")
        cont = self._continuation(answer.get("continue"), "continue")
        pending = PendingGrant(
            id=client_nonce,
            client_nonce=client_nonce,
            server_nonce=finish,
            hash_method="sha-256",
            continuation=cont,
            continue_not_before=time.time() * 1000 + (cont.wait or 0) * 1000,
            grant_endpoint=self.config.grant_endpoint,
            created_at=time.time() * 1000,
        )
        if context is not None:
            pending.context = context
        if self._instance_id:
            pending.instance_id = self._instance_id
        if expected_sub:
            pending.expected_sub = expected_sub
        self._sweep()
        self._pending[pending.id] = pending
        return pending

    def _match(self, digest, interact_ref, allowed_ids=None):
        if digest in self._used:
            raise GnapError("validation", "this interaction finish was already used")
        for pending in self._pending.values():
            if allowed_ids is not None and pending.id not in allowed_ids:
                continue
            expected = interaction_hash(pending.client_nonce, pending.server_nonce, interact_ref, pending.grant_endpoint)
            if not hash_equal(digest, expected):
                continue
            if time.time() * 1000 - pending.created_at > self.config.transaction_ttl_sec * 1000:
                self._pending.pop(pending.id, None)
                raise GnapError("validation", "the approval took too long; start again", context=getattr(pending, "context", None))
            return pending
        raise GnapError(
            "validation",
            "this finish is not a sign-in this browser started" if allowed_ids is not None else "the interaction hash matches no grant in progress",
        )

    def _finish(self, pending, interact_ref, digest):
        self._pending.pop(pending.id, None)
        self._used[digest] = None
        if len(self._used) > 1000:
            self._used.pop(next(iter(self._used)))
        due = pending.continue_not_before - time.time() * 1000
        if due > 0:
            time.sleep(min(due, self.config.max_wait_sec * 1000) / 1000)
        try:
            answer = self._continue(pending.continuation, {"interact_ref": interact_ref})
        except GnapError as err:
            err.context = getattr(pending, "context", None)
            raise
        if not self._has_token(answer):
            raise GnapError("protocol", "the resource owner did not approve the grant", gnap_error="user_denied", context=getattr(pending, "context", None))
        try:
            grant = self._grant_from(answer, {"previous_continue": pending.continuation})
            self._expect(grant, getattr(pending, "expected_sub", None))
            return FinishedGrant(grant, getattr(pending, "context", None))
        except GnapError as err:
            err.context = getattr(pending, "context", None)
            raise

    def _continue(self, cont, body):
        current = cont
        waited = 0
        immediate = 0
        while True:
            try:
                return self._signed_json("POST", current.uri, body=body, token=current.access_token)
            except GnapError as err:
                if err.gnap_error != "too_fast":
                    raise
                if err.continuation:
                    self._check_same_origin(err.continuation.uri, "continue.uri")
                    current = Continuation(err.continuation.uri, err.continuation.access_token, err.continuation.wait)
                wait = max(0, float(current.wait or 0))
                if wait == 0:
                    immediate += 1
                    if immediate > 2:
                        raise
                    continue
                if waited + wait > self.config.max_wait_sec:
                    raise
                time.sleep(wait)
                waited += wait

    def _signed_json(self, method, url, body=None, token=None):
        self._check_same_origin(url, "the request URL")
        text = None if body is None else dumps(body)
        extra = {"content-type": "application/json"} if text is not None else None
        headers = self._proof_headers(method, url, text, token, extra)
        headers["accept"] = "application/json"
        answer = send(url, method=method, headers=headers, body=text, tls=self.tls(), code="protocol")
        return self._read(answer)

    def _proof_headers(self, method, url, body, token, extra=None):
        headers = dict(extra or {})
        if token:
            headers["authorization"] = f"GNAP {token}"
        if self.config.key.proof == "httpsig":
            headers.update(sign_request(self.config.key, method, url, headers, body))
        elif self.config.key.proof == "jwsd":
            headers["detached-jws"] = detached_jws(self.config.key, method, url, body, token)
        return headers

    def _read(self, answer):
        if answer.status == 204 or not answer.body:
            if answer.status >= 400:
                raise GnapError("protocol", f"the authorization server answered {answer.status}")
            return None
        try:
            parsed = json.loads(answer.body)
        except Exception as err:
            raise GnapError("protocol", f"the authorization server answered {answer.status} with a body that is not JSON", cause=err) from err
        if 200 <= answer.status < 300:
            return parsed
        doc = parsed if isinstance(parsed, dict) else {}
        code = doc.get("error") if isinstance(doc.get("error"), str) else None
        continuation = None
        raw = doc.get("continue")
        if isinstance(raw, dict):
            token = (raw.get("access_token") or {}).get("value") if isinstance(raw.get("access_token"), dict) else None
            if isinstance(raw.get("uri"), str) and isinstance(token, str):
                continuation = ErrorContinuation(raw["uri"], token, raw.get("wait") if is_number(raw.get("wait")) else None)
        description = doc.get("error_description") if isinstance(doc.get("error_description"), str) and doc.get("error_description") else None
        raise GnapError(
            "protocol",
            description or code or f"the authorization server answered {answer.status}",
            gnap_error=code,
            continuation=continuation,
        )

    def _has_token(self, answer):
        return isinstance(answer, dict) and bool(answer.get("access_token"))

    def _grant_from(self, answer, previous):
        doc = answer if isinstance(answer, dict) else {}
        token = doc.get("access_token")
        if isinstance(token, list):
            token = token[0] if token else None
        if not isinstance(token, dict):
            raise GnapError("protocol", "the access token is not an object")
        if not isinstance(token.get("value"), str) or not token.get("value"):
            raise GnapError("protocol", "the access token has no value")
        flags = [str(item) for item in token["flags"]] if isinstance(token.get("flags"), list) else []
        bearer = "bearer" in flags
        if bearer and self.config.require_bound_tokens:
            raise GnapError("validation", "the authorization server issued a bearer token, and this client requires a key-bound one")
        self._remember_instance(answer)
        manage = None
        if isinstance(token.get("manage"), dict):
            raw = token["manage"]
            value = (raw.get("access_token") or {}).get("value") if isinstance(raw.get("access_token"), dict) else None
            if not isinstance(raw.get("uri"), str) or not isinstance(value, str):
                raise GnapError("protocol", "the access token manage object is not usable")
            self._check_same_origin(raw["uri"], "manage.uri")
            manage = Continuation(raw["uri"], value)
        elif previous.get("previous") and previous["previous"].manage:
            manage = previous["previous"].manage
        if doc.get("continue"):
            cont = self._continuation(doc.get("continue"), "continue")
        elif previous.get("previous_continue"):
            cont = previous["previous_continue"]
        elif previous.get("previous") and previous["previous"].continuation:
            cont = previous["previous"].continuation
        else:
            cont = None
        audiences = [item for item in (self._instance_id, self.config.application) if item]
        if doc.get("subject"):
            subject = person_from(doc.get("subject"), {
                "id_token_issuer": self.config.id_token_issuer,
                "audiences": audiences,
                "clock_tolerance_sec": self.config.clock_tolerance_sec,
                "keys": self._id_token_keys,
            })
        else:
            subject = previous["previous"].subject if previous.get("previous") else None
        expires_in = token.get("expires_in") if is_number(token.get("expires_in")) else None
        return Grant(
            token["value"], bearer, token.get("access"),
            expires_in, (time.time() * 1000 + expires_in * 1000) if expires_in is not None else None,
            manage, cont, self._instance_id, subject, _grant_id(cont.uri if cont else None),
        )

    def _expect(self, grant, expected_sub):
        if expected_sub and grant.subject and grant.subject.sub != expected_sub:
            raise GnapError("validation", "the grant was approved by somebody other than the account that was asked for")

    def _continuation(self, raw, what):
        if not isinstance(raw, dict):
            raise GnapError("protocol", f"the response has no {what} object")
        value = (raw.get("access_token") or {}).get("value") if isinstance(raw.get("access_token"), dict) else None
        if not isinstance(raw.get("uri"), str) or not isinstance(value, str):
            raise GnapError("protocol", f"the response has no usable {what} object")
        self._check_same_origin(raw["uri"], f"{what}.uri")
        if "wait" in raw and raw["wait"] is not None and not (is_number(raw["wait"]) and raw["wait"] >= 0):
            raise GnapError("protocol", f"{what}.wait is not a number of seconds")
        return Continuation(raw["uri"], value, raw["wait"] if is_number(raw.get("wait")) else None)

    def _check_same_origin(self, uri, what):
        try:
            parts = urlsplit(uri)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ValueError(uri)
        except Exception:
            raise GnapError("validation", f"{what} is not a URL: {uri}") from None
        if parts.scheme != "https" and not self.config.allow_insecure:
            raise GnapError("validation", f"{what} must use https: {uri}")
        if origin_of(uri) != origin_of(self.config.grant_endpoint):
            raise GnapError("validation", f"{what} {uri} is not on the grant endpoint's origin")

    def _id_token_keys(self):
        if self._jwks is not None:
            return self._jwks
        metadata = discover_open_id(self.config.id_token_issuer, self.tls())
        answer = send(metadata["jwks_uri"], headers={"accept": "application/json"}, tls=self.tls(), code="discovery")
        try:
            parsed = json.loads(answer.body)
        except Exception as err:
            raise GnapError("discovery", "the issuer JWKS is not JSON", cause=err) from err
        if answer.status != 200 or not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
            raise GnapError("discovery", f"the issuer JWKS answered {answer.status}")
        self._jwks = parsed["keys"]
        return self._jwks

    def _sweep(self):
        cutoff = time.time() * 1000 - self.config.transaction_ttl_sec * 1000
        for identifier, pending in list(self._pending.items()):
            if pending.created_at < cutoff:
                del self._pending[identifier]
        while len(self._pending) > 1000:
            oldest = next(iter(self._pending), None)
            if oldest is None:
                break
            del self._pending[oldest]
