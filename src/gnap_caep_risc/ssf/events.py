# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""CAEP, RISC, and SSF event types, and what an event's subject names."""

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISC = "https://schemas.openid.net/secevent/risc/event-type/"
SSF = "https://schemas.openid.net/secevent/ssf/event-type/"


class Event:
    session_revoked = f"{CAEP}session-revoked"
    token_claims_change = f"{CAEP}token-claims-change"
    credential_change = f"{CAEP}credential-change"
    assurance_level_change = f"{CAEP}assurance-level-change"
    device_compliance_change = f"{CAEP}device-compliance-change"
    session_established = f"{CAEP}session-established"
    session_presented = f"{CAEP}session-presented"
    risk_level_change = f"{CAEP}risk-level-change"
    account_credential_change_required = f"{RISC}account-credential-change-required"
    account_purged = f"{RISC}account-purged"
    account_disabled = f"{RISC}account-disabled"
    account_enabled = f"{RISC}account-enabled"
    identifier_changed = f"{RISC}identifier-changed"
    identifier_recycled = f"{RISC}identifier-recycled"
    credential_compromise = f"{RISC}credential-compromise"
    opt_in = f"{RISC}opt-in"
    opt_out_initiated = f"{RISC}opt-out-initiated"
    opt_out_cancelled = f"{RISC}opt-out-cancelled"
    opt_out_effective = f"{RISC}opt-out-effective"
    recovery_activated = f"{RISC}recovery-activated"
    recovery_information_changed = f"{RISC}recovery-information-changed"
    sessions_revoked = f"{RISC}sessions-revoked"
    verification = f"{SSF}verification"
    stream_updated = f"{SSF}stream-updated"


EVENT = Event()

CAEP_EVENTS = [value for name, value in vars(Event).items() if not name.startswith("_") and isinstance(value, str) and value.startswith(CAEP)]
RISC_EVENTS = [value for name, value in vars(Event).items() if not name.startswith("_") and isinstance(value, str) and value.startswith(RISC)]

DEFAULT_EVENTS_REQUESTED = [
    Event.session_revoked, Event.credential_change, Event.assurance_level_change, Event.token_claims_change,
    Event.account_disabled, Event.account_enabled, Event.account_purged, Event.credential_compromise,
    Event.sessions_revoked, Event.account_credential_change_required,
]

DEFAULT_ENDING_EVENTS = [
    Event.session_revoked, Event.account_disabled, Event.account_purged, Event.credential_compromise, Event.sessions_revoked,
]


def _simple(identifier, issuer):
    if not isinstance(identifier, dict):
        return {}
    fmt = str(identifier.get("format") or identifier.get("subject_type") or "")
    if fmt == "iss_sub" and isinstance(identifier.get("sub"), str) and (identifier.get("iss") is None or identifier.get("iss") == issuer):
        return {"sub": identifier["sub"]}
    if fmt == "email" and isinstance(identifier.get("email"), str):
        return {"email": identifier["email"]}
    if fmt == "opaque" and isinstance(identifier.get("id"), str):
        return {"opaque": identifier["id"]}
    if fmt == "aliases" and isinstance(identifier.get("identifiers"), list):
        merged = {}
        for one in identifier["identifiers"]:
            merged.update(_simple(one, issuer))
        return merged
    return {}


def subject_of(sub_id, issuer) -> dict:
    if not isinstance(sub_id, dict):
        return {}
    fmt = str(sub_id.get("format") or sub_id.get("subject_type") or "")
    if fmt == "complex" or (not fmt and (sub_id.get("user") or sub_id.get("session"))):
        user = _simple(sub_id.get("user"), issuer)
        session = _simple(sub_id.get("session"), issuer)
        out = {}
        if user.get("sub"):
            out["person"] = user["sub"]
        if user.get("email"):
            out["email"] = user["email"]
        session_id = session.get("opaque") or session.get("sub")
        if session_id:
            out["idp_session"] = session_id
        return out
    one = _simple(sub_id, issuer)
    out = {}
    if one.get("sub"):
        out["person"] = one["sub"]
    if one.get("email"):
        out["email"] = one["email"]
    return out
