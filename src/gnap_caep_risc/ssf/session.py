# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Which local sessions belong to which person and which provider session."""

import time


class TrackedSession:
    def __init__(self, local_id, person=None, email=None, idp_session=None, expires_at=None):
        self.local_id = local_id
        self.person = person
        self.email = email
        self.idp_session = idp_session
        self.expires_at = expires_at


def _epoch(value):
    """Milliseconds, matching Date.now() and a grant's expires_at."""
    if value is None:
        return None
    if hasattr(value, "timestamp"):
        return value.timestamp() * 1000
    return value


class MemorySessionIndex:
    def __init__(self, max_sessions=100_000):
        self._sessions = {}
        self._max = max_sessions

    def add(self, session: TrackedSession):
        if len(self._sessions) >= self._max and session.local_id not in self._sessions:
            now = time.time() * 1000
            for key, value in list(self._sessions.items()):
                if value.expires_at is not None and value.expires_at <= now:
                    del self._sessions[key]
            while len(self._sessions) >= self._max:
                oldest = next(iter(self._sessions), None)
                if oldest is None:
                    break
                del self._sessions[oldest]
        self._sessions[session.local_id] = TrackedSession(
            session.local_id, session.person,
            session.email.lower() if isinstance(session.email, str) else session.email,
            session.idp_session, _epoch(session.expires_at),
        )

    def remove(self, local_id):
        self._sessions.pop(local_id, None)

    def _find(self, match):
        now = time.time() * 1000
        out = []
        for key, value in list(self._sessions.items()):
            if value.expires_at is not None and value.expires_at <= now:
                del self._sessions[key]
                continue
            if match(value):
                out.append(key)
        return out

    def by_person(self, person):
        return self._find(lambda session: session.person == person)

    def by_email(self, email):
        wanted = email.lower()
        return self._find(lambda session: session.email == wanted)

    def by_idp_session(self, idp_session):
        return self._find(lambda session: session.idp_session == idp_session)


def tracked_from_person(local_id, person, expires_at=None) -> TrackedSession:
    return TrackedSession(
        local_id,
        getattr(person, "sub", None) if not isinstance(person, dict) else person.get("sub"),
        (getattr(person, "email", None) if not isinstance(person, dict) else person.get("email")) or None,
        (getattr(person, "sid", None) if not isinstance(person, dict) else person.get("sid")) or None,
        expires_at,
    )
