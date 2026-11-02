# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""A Shared Signals receiver (OpenID SSF 1.0, RFC 8936 poll delivery) for one application's stream."""

import json
import re
import threading
import time
from concurrent.futures import Future

from ..discovery import well_known_urls
from ..errors import GnapError
from ..http import send
from .events import DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subject_of
from .jws import verify_compact_jws
from .session import MemorySessionIndex

POLL_METHOD = "urn:ietf:rfc:8936"


class _Log:
    def info(self, message):
        print(message)

    def warn(self, message):
        print(message)

    def error(self, message):
        print(message)


class SignalEvent:
    def __init__(self, type, payload, subject, jti, sessions, ended, iat=None, txn=None):
        self.type = type
        self.payload = payload
        self.subject = subject
        self.jti = jti
        self.sessions = sessions
        self.ended = ended
        self.iat = iat
        self.txn = txn


class SignalsReceiver:
    def __init__(self, transmitter, on_end_sessions, tls=None, headers=None, events_requested=None,
                 end_on=None, session_index=None, description=None, poll_interval_ms=5000, max_events=50, log=None):
        if not callable(on_end_sessions):
            raise GnapError("config", "onEndSessions is required")
        if not isinstance(transmitter, str) or not (transmitter.startswith("https://") or transmitter.startswith("http://")):
            raise GnapError("config", "transmitter must be an http(s) URL")
        self._transmitter = transmitter.rstrip("/")
        self._tls = tls or {}
        self._headers = headers
        self._events_requested = list(events_requested) if events_requested is not None else list(DEFAULT_EVENTS_REQUESTED)
        self._end_on = list(end_on) if end_on is not None else list(DEFAULT_ENDING_EVENTS)
        self._description = description
        self._poll_interval_ms = poll_interval_ms
        self._max_events = max_events
        self._log = log or _Log()
        self._on_end = on_end_sessions
        self._index = session_index or MemorySessionIndex()
        self._config = None
        self._stream = None
        self._keys = []
        self._keys_at = 0
        self._timer = None
        self._running = False
        self._ack = []
        self._errs = {}
        self._inflight = None
        self._gate = threading.Lock()
        self._handlers = {}

    @property
    def stream(self):
        return self._stream

    def track(self, session):
        self._index.add(session)

    def untrack(self, local_id):
        self._index.remove(local_id)

    def on(self, type, handler):
        self._handlers.setdefault(type, []).append(handler)
        return self

    def _call(self, method, url, body=None):
        text = None if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        extra = {}
        if self._headers:
            request = {"method": method, "url": url}
            if text is not None:
                request["body"] = text
            extra = self._headers(request) or {}
        headers = {"accept": "application/json", **extra}
        if text is not None and "content-type" not in {name.lower() for name in headers}:
            headers["content-type"] = "application/json"
        answer = send(url, method=method, headers=headers, body=text, tls=self._tls, code="ssf")
        parsed = None
        if answer.body:
            try:
                parsed = json.loads(answer.body)
            except Exception:
                parsed = answer.body
        return answer.status, parsed

    def _discover(self):
        urls = well_known_urls(self._transmitter, "ssf-configuration")
        last = GnapError("ssf", f"no transmitter configuration at {' or '.join(urls)}")
        for url in urls:
            status, doc = self._call("GET", url)
            if status == 404 and url != urls[-1]:
                continue
            if status != 200 or not isinstance(doc, dict) or not doc.get("configuration_endpoint") or not doc.get("jwks_uri"):
                last = GnapError("ssf", f"{url} answered {status} without a usable transmitter configuration")
                continue
            methods = doc.get("delivery_methods_supported")
            if methods and POLL_METHOD not in methods:
                raise GnapError("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
            return doc
        raise last

    def _jwks(self, force=False):
        if not force and self._keys and time.time() * 1000 - self._keys_at < 3_600_000:
            return self._keys
        status, doc = self._call("GET", self._config["jwks_uri"])
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if status != 200 or not isinstance(keys, list):
            raise GnapError("ssf", f"the transmitter's JWKS answered {status}")
        self._keys = keys
        self._keys_at = time.time() * 1000
        return keys

    def _ensure_stream(self):
        endpoint = self._config["configuration_endpoint"]
        status, listed = self._call("GET", endpoint)
        if status == 200:
            all_streams = listed if isinstance(listed, list) else ([listed] if listed else [])
            mine = next((stream for stream in all_streams if isinstance(stream, dict) and (stream.get("delivery") or {}).get("method") == POLL_METHOD and stream.get("stream_id")), None)
            if mine:
                return mine
        elif status != 404:
            raise GnapError("ssf", f"listing the streams at {endpoint} answered {status}: {json.dumps(listed)[:300]}")
        payload = {"delivery": {"method": POLL_METHOD}, "events_requested": self._events_requested}
        if self._description:
            payload["description"] = self._description
        status, created = self._call("POST", endpoint, payload)
        if status not in (200, 201) or not isinstance(created, dict) or not created.get("stream_id"):
            raise GnapError("ssf", f"creating a stream at {endpoint} answered {status}: {json.dumps(created)[:300]}")
        return created

    def start(self):
        if self._running:
            return
        self._config = self._discover()
        self._jwks(True)
        self._stream = self._ensure_stream()
        endpoint = (self._stream.get("delivery") or {}).get("endpoint_url")
        if not endpoint:
            raise GnapError("ssf", "the stream has no poll endpoint_url")
        self._running = True
        delivered = self._stream.get("events_delivered") or []
        self._log.info(f"ssf: polling stream {self._stream.get('stream_id')} at {endpoint}, delivering {len(delivered)} event type(s)")
        self._loop()

    def stop(self):
        self._running = False
        timer = self._timer
        self._timer = None
        if timer is not None:
            timer.cancel()

    def _loop(self):
        if not self._running:
            return
        delay = self._poll_interval_ms
        try:
            more = self.poll_once()
            if more:
                delay = 0
        except Exception as err:
            self._log.warn(f"ssf: poll failed: {err}")
            delay = min(self._poll_interval_ms * 4, 60_000)
        if self._running:
            timer = threading.Timer(delay / 1000, self._loop)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def poll_once(self) -> bool:
        with self._gate:
            if self._inflight is not None:
                future = self._inflight
                owner = False
            else:
                future = self._inflight = Future()
                owner = True
        if not owner:
            return future.result()
        try:
            result = self._poll_now()
        except Exception as exc:
            future.set_exception(exc)
            raise
        else:
            future.set_result(result)
            return result
        finally:
            with self._gate:
                if self._inflight is future:
                    self._inflight = None

    def _poll_now(self) -> bool:
        url = self._stream["delivery"]["endpoint_url"]
        ack = self._ack
        self._ack = []
        set_errs = self._errs
        self._errs = {}
        body = {"maxEvents": self._max_events, "returnImmediately": True}
        if ack:
            body["ack"] = ack
        if set_errs:
            body["setErrs"] = set_errs
        status, answer = self._call("POST", url, body)
        if status != 200:
            self._ack = ack + self._ack
            self._errs = {**set_errs, **self._errs}
            raise GnapError("ssf", f"the poll answered {status}: {json.dumps(answer)[:300]}")
        doc = answer if isinstance(answer, dict) else {}
        sets = doc.get("sets") or {}
        for jti, token in sets.items():
            try:
                self._handle(jti, token)
                self._ack.append(jti)
            except Exception as err:
                description = str(err)
                self._log.warn(f"ssf: SET {jti} refused: {description}")
                code = "invalid_key" if isinstance(err, GnapError) and err.code == "signature" else "invalid_request"
                self._errs[jti] = {"err": code, "description": description}
        return bool(doc.get("moreAvailable"))

    def _handle(self, jti, token):
        try:
            verified = verify_compact_jws(token, self._jwks())
        except GnapError as err:
            if not re.search(r"publishes no|signing key|does not verify", str(err)):
                raise
            verified = verify_compact_jws(token, self._jwks(True))
        header = verified["header"]
        payload = verified["payload"]
        if header.get("typ") is not None and str(header.get("typ")).lower() != "secevent+jwt":
            raise GnapError("validation", f"the SET's typ is {header.get('typ')}")
        if payload.get("iss") != self._config.get("issuer"):
            raise GnapError("validation", f"the SET was issued by {payload.get('iss')}, not {self._config.get('issuer')}")
        want = self._stream.get("aud")
        want_list = want if isinstance(want, list) else ([] if want is None else [want])
        aud = payload.get("aud")
        aud_list = [str(item) for item in (aud if isinstance(aud, list) else ([] if aud is None else [aud]))]
        if want_list and not any(one in [str(item) for item in want_list] for one in aud_list):
            raise GnapError("validation", f"the SET is for {', '.join(aud_list)}, not this stream")
        if "jti" in payload and payload.get("jti") is not None and payload.get("jti") != jti:
            raise GnapError("validation", "the SET's jti is not the one it was delivered under")
        events = payload.get("events")
        if not isinstance(events, dict) or not events:
            raise GnapError("validation", "the SET carries no events")
        for type, body in events.items():
            subject = subject_of(payload.get("sub_id") if payload.get("sub_id") is not None else (body or {}).get("subject") if isinstance(body, dict) else None, self._config.get("issuer"))
            sessions = self._sessions_for(type, subject)
            ends = type in self._end_on and len(sessions) > 0
            event = SignalEvent(
                type, body or {}, subject, jti, sessions, ends,
                payload.get("iat") if isinstance(payload.get("iat"), (int, float)) and not isinstance(payload.get("iat"), bool) else None,
                payload.get("txn") if isinstance(payload.get("txn"), str) else None,
            )
            if ends:
                try:
                    self._on_end(sessions, event)
                except Exception as err:
                    self._log.error(f"ssf: onEndSessions threw for {type} (SET {jti} is still acknowledged): {err}")
                    event.ended = False
                if event.ended:
                    for local_id in sessions:
                        self._index.remove(local_id)
            for handler in [*(self._handlers.get(type) or []), *(self._handlers.get("*") or [])]:
                try:
                    handler(event)
                except Exception as err:
                    self._log.error(f"ssf: a handler for {type} threw (SET {jti} is still acknowledged): {err}")

    def _sessions_for(self, type, subject):
        if type in (EVENT.verification, EVENT.stream_updated):
            return []
        if subject.get("idp_session"):
            found = self._index.by_idp_session(subject["idp_session"])
            if found or type == EVENT.session_revoked:
                return found
        if subject.get("person"):
            return self._index.by_person(subject["person"])
        if subject.get("email"):
            return self._index.by_email(subject["email"])
        return []

    def verify(self, state=None):
        endpoint = (self._config or {}).get("verification_endpoint")
        if not isinstance(endpoint, str):
            raise GnapError("ssf", "the transmitter publishes no verification_endpoint")
        body = {"stream_id": self._stream["stream_id"]}
        if state:
            body["state"] = state
        status, _answer = self._call("POST", endpoint, body)
        if status not in (200, 204):
            raise GnapError("ssf", f"verification answered {status}")
