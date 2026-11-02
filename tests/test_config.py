# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from gnap_caep_risc import GnapError, resolve_config

PRIVATE = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode("ascii")


def resolve(extra=None):
    body = {
        "grantEndpoint": "https://idp.example/gnap",
        "application": "app",
        "privateKey": PRIVATE,
        "keyProof": "httpsig",
    }
    body.update(extra or {})
    return resolve_config(body, ".")


def test_defaults_access_and_fills_transmitter():
    resolved = resolve({"transmitterIssuer": "https://idp.example/issuer/"})
    assert resolved.access == ["ssf.read", "ssf.manage"]
    assert resolved.ssf == {"transmitter": "https://idp.example/issuer"}
    assert not hasattr(resolved, "signals")
    on = resolve({"signals": True, "transmitterIssuer": "https://idp.example/issuer"})
    assert not hasattr(on, "signals")
    assert on.ssf


def test_drops_ssf_rights_and_transmitter_when_signals_is_false():
    resolved = resolve({
        "signals": False,
        "access": ["openid", "ssf.read"],
        "transmitterIssuer": "https://idp.example",
        "ssf": {"transmitter": "https://idp.example/tx", "pollIntervalMs": 3000},
    })
    assert resolved.access == ["openid"]
    assert not hasattr(resolved, "ssf")
    assert resolved.signals is False
    kept = resolve({
        "signals": False,
        "access": ["openid", " ssf.read ", {"type": "ssf.manage", "actions": ["read"]}, {"type": "api"}, {"type": " ssf.read "}],
        "ssf": {"transmitter": "not a url"},
    })
    assert kept.access == ["openid", {"type": "api"}, {"type": " ssf.read "}]
    assert not hasattr(kept, "ssf")


def test_refuses_signals_off_when_ssf_rights_were_the_only_ones():
    message = "signals is false and access has no rights left after ssf.read and ssf.manage were removed"
    with pytest.raises(GnapError, match=message) as caught:
        resolve({"signals": False, "access": ["ssf.read", "ssf.manage"]})
    assert caught.value.code == "config"
    assert "must name a right this authorization server grants" in str(caught.value)
    with pytest.raises(GnapError, match=message):
        resolve({"signals": False, "transmitterIssuer": "https://idp.example"})
    with pytest.raises(GnapError, match=message):
        resolve({"signals": False, "access": [{"type": "ssf.read"}, {"type": "ssf.manage"}]})


def test_refuses_a_signals_value_that_is_not_true_or_false():
    with pytest.raises(GnapError) as caught:
        resolve({"signals": "no"})
    assert caught.value.code == "config"
    assert str(caught.value) == "signals must be true or false"
