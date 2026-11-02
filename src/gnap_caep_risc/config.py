# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Configuration. JSON keys match the Node library so the same gnap.json loads.

`signals` omitted or true keeps CAEP and RISC on. false drops ssf.read and ssf.manage and does not
fill a transmitter. The resolved object omits signals when they are on.
"""

import json
import os
from pathlib import Path

from .discovery import href_of, is_loopback
from .errors import GnapError
from .keys import PROOFS, load_client_key

SSF_RIGHTS = ("ssf.read", "ssf.manage")


class ResolvedConfig:
    """Attributes are set only when present. `signals` exists only when it is false."""


def _object(raw):
    if not isinstance(raw, dict):
        raise GnapError("config", "the configuration must be a JSON object")
    return raw


def _read_path(path: str, base: Path, what: str) -> str:
    full = Path(path) if Path(path).is_absolute() else base / path
    try:
        return full.read_text(encoding="utf-8")
    except Exception as err:
        raise GnapError("config", f"could not read {what} at {full}: {err}", cause=err) from err


def _secret(raw: str, base: Path, what: str) -> str:
    if raw.startswith("env:"):
        name = raw[4:]
        value = os.environ.get(name)
        if not value:
            raise GnapError("config", f"{what} reads {name}, and that variable is empty")
        return value
    if raw.startswith("file:"):
        return _read_path(raw[5:], base, what)
    return raw


def _key_value(raw: str, base: Path, what: str) -> str:
    if raw.startswith("env:") or raw.startswith("file:") or "-----BEGIN" in raw:
        return _secret(raw, base, what)
    return _read_path(raw, base, what)


def read_trust(raw, base: Path):
    if not raw:
        return None
    if "-----BEGIN" in raw:
        return raw
    if raw.startswith("env:"):
        return os.environ.get(raw[4:]) or None
    path = raw[5:] if raw.startswith("file:") else raw
    full = Path(path) if Path(path).is_absolute() else base / path
    try:
        return full.read_text(encoding="utf-8")
    except Exception:
        return None


def _ssf_right(right) -> bool:
    if isinstance(right, str):
        return right.strip() in SSF_RIGHTS
    if not isinstance(right, dict):
        return False
    return right.get("type") in SSF_RIGHTS


def _check_url(value: str, name: str, allow_http: bool) -> str:
    try:
        href = href_of(value)
        parts_scheme = href.split(":", 1)[0]
    except Exception:
        raise GnapError("config", f"{name} is not a URL: {value}") from None
    if parts_scheme == "https":
        return href
    if parts_scheme == "http" and allow_http:
        return href
    extra = "" if allow_http else ", or http on loopback"
    raise GnapError("config", f"{name} must use https{extra}: {value}")


def resolve_config(raw, base_dir) -> ResolvedConfig:
    doc = _object(raw)
    if "signals" in doc and not isinstance(doc["signals"], bool):
        raise GnapError("config", "signals must be true or false")
    signals_off = doc.get("signals") is False
    application = str(doc.get("application") or "").strip()
    if not application:
        raise GnapError("config", "application is required: the registered GNAP client")
    grant_raw = str(doc.get("grantEndpoint") or "").strip()
    if not grant_raw:
        raise GnapError("config", "grantEndpoint is required")
    allow_insecure = doc.get("allowInsecure") is True
    grant_endpoint = _check_url(grant_raw, "grantEndpoint", allow_insecure)
    from urllib.parse import urlsplit
    origin = f"{urlsplit(grant_endpoint).scheme}://{urlsplit(grant_endpoint).netloc}"
    id_token_issuer = (str(doc.get("idTokenIssuer") or "").strip() or origin).rstrip("/")
    if not (id_token_issuer.startswith("https://") or id_token_issuer.startswith("http://")):
        raise GnapError("config", "idTokenIssuer must be an http(s) URL")
    proof_raw = str(doc.get("keyProof") or "").strip()
    if proof_raw and proof_raw not in PROOFS:
        raise GnapError("config", f"keyProof must be {', '.join(PROOFS)}, not {proof_raw}")
    if not doc.get("privateKey"):
        raise GnapError("config", "privateKey is required")
    base = Path(base_dir)
    private_key = _key_value(doc["privateKey"], base, "the private key")
    certificate = _key_value(doc["certificate"], base, "the certificate") if doc.get("certificate") else None
    key = load_client_key(private_key, certificate, proof_raw or None)
    if key.proof == "mtls" and urlsplit(grant_endpoint).scheme != "https":
        raise GnapError("config", "mutual TLS needs an https grant endpoint")
    finish_method = doc.get("finishMethod") or "redirect"
    if finish_method not in ("redirect", "push"):
        raise GnapError("config", "finishMethod must be redirect or push")
    finish_raw = str(doc.get("finishUri") or "").strip()
    finish_loopback = False
    if finish_raw:
        try:
            finish_loopback = is_loopback(finish_raw)
        except Exception:
            finish_loopback = False
    finish_uri = _check_url(finish_raw, "finishUri", allow_insecure or finish_loopback) if finish_raw else None
    hash_method = doc.get("hashMethod") or "sha-256"
    if hash_method != "sha-256":
        raise GnapError("config", "hashMethod must be sha-256")
    interaction = doc.get("interactionStart") if doc.get("interactionStart") is not None else ["redirect"]
    if not isinstance(interaction, list) or not interaction or any(not mode for mode in interaction):
        raise GnapError("config", "interactionStart must name at least one mode")
    requested = doc.get("access") if doc.get("access") is not None else ["ssf.read", "ssf.manage"]
    if not isinstance(requested, list):
        raise GnapError("config", "access must list at least one right")
    access = [right for right in requested if not _ssf_right(right)] if signals_off else list(requested)
    if not access:
        raise GnapError(
            "config",
            "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller must name a right this authorization server grants"
            if signals_off else "access must list at least one right",
        )
    tls_ca = read_trust(doc.get("tlsCa"), base)
    ssf = None
    if not signals_off:
        raw_ssf = doc.get("ssf") if isinstance(doc.get("ssf"), dict) else {}
        transmitter = raw_ssf.get("transmitter") or doc.get("transmitterIssuer")
        if isinstance(transmitter, str):
            transmitter = transmitter.rstrip("/")
        if transmitter:
            if not (transmitter.startswith("https://") or transmitter.startswith("http://")):
                raise GnapError("config", "ssf.transmitter must be an http(s) URL")
            ssf = {"transmitter": transmitter}
            if raw_ssf.get("pollIntervalMs"):
                ssf["pollIntervalMs"] = raw_ssf["pollIntervalMs"]
    display_in = doc.get("display") if isinstance(doc.get("display"), dict) else None
    display = None
    if display_in and (display_in.get("name") or display_in.get("uri")):
        display = {}
        if display_in.get("name"):
            display["name"] = display_in["name"]
        if display_in.get("uri"):
            display["uri"] = display_in["uri"]
    out = ResolvedConfig()
    out.grant_endpoint = grant_endpoint
    out.id_token_issuer = id_token_issuer
    out.application = application
    if doc.get("classId"):
        out.class_id = doc["classId"]
    if display:
        out.display = display
    out.access = access
    if signals_off:
        out.signals = False
    out.sub_id_formats = list(doc.get("subIdFormats") or ["iss_sub", "account", "opaque"])
    out.assertion_formats = list(doc.get("assertionFormats") or ["id_token"])
    out.key = key
    if finish_uri:
        out.finish_uri = finish_uri
    out.finish_method = finish_method
    out.interaction_start = list(interaction)
    out.hash_method = "sha-256"
    out.require_bound_tokens = doc.get("requireBoundTokens") is not False
    out.use_instance_id = doc.get("useInstanceId") is not False
    if tls_ca:
        out.tls_ca = tls_ca
    out.allow_insecure = allow_insecure
    out.clock_tolerance_sec = doc["clockToleranceSec"] if "clockToleranceSec" in doc and doc["clockToleranceSec"] is not None else 30
    out.max_wait_sec = doc["maxWaitSec"] if "maxWaitSec" in doc and doc["maxWaitSec"] is not None else 30
    out.transaction_ttl_sec = doc["transactionTtlSec"] if "transactionTtlSec" in doc and doc["transactionTtlSec"] is not None else 600
    if ssf:
        out.ssf = ssf
    # JSON names are kept beside the attributes so a caller can read either shape.
    out.grantEndpoint = grant_endpoint
    out.idTokenIssuer = id_token_issuer
    out.subIdFormats = out.sub_id_formats
    out.assertionFormats = out.assertion_formats
    out.finishUri = getattr(out, "finish_uri", None)
    out.finishMethod = finish_method
    out.interactionStart = out.interaction_start
    out.hashMethod = "sha-256"
    out.requireBoundTokens = out.require_bound_tokens
    out.useInstanceId = out.use_instance_id
    out.allowInsecure = allow_insecure
    out.clockToleranceSec = out.clock_tolerance_sec
    out.maxWaitSec = out.max_wait_sec
    out.transactionTtlSec = out.transaction_ttl_sec
    if doc.get("classId"):
        out.classId = doc["classId"]
    if tls_ca:
        out.tlsCa = tls_ca
    return out


def read_config_file(path: str) -> ResolvedConfig:
    file = Path(path)
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except Exception as err:
        raise GnapError("config", f"could not read {path}: {err}", cause=err) from err
    return resolve_config(raw, file.resolve().parent)
