# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Interaction finish hash, RFC 9635 section 4.2.3. The continuation token never leaves this process."""

from .codec import b64url, sha256, timing_equal


def interaction_hash(client_nonce: str, server_nonce: str, interact_ref: str, grant_endpoint: str) -> str:
    """base64url(SHA-256(clientNonce + newline + serverNonce + newline + interact_ref + newline + grant endpoint))."""
    raw = f"{client_nonce}\n{server_nonce}\n{interact_ref}\n{grant_endpoint}".encode("utf-8")
    return b64url(sha256(raw))


def hash_equal(a: str, b: str) -> bool:
    return timing_equal(a, b)
