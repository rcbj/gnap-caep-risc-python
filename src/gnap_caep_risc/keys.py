# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The one client key. It is presented by value on the first grant and proved on every request.

A JWK's kid is its RFC 7638 thumbprint. A certificate's identity is the SHA-256 of its DER (x5t#S256).
ECDSA signatures are raw R||S. RSA-PSS salt length is the digest length.
"""

import hashlib
import json
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .codec import b64url
from .errors import GnapError

PROOFS = ("mtls", "httpsig", "jwsd")
CURVE_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
HASHES = {
    "ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512(),
    "RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512(),
    "PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512(),
}
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


class ClientKey:
    def __init__(self, proof, private_key, thumbprint, alg, kid, jwk=None, certificate_pem=None, tls_chain_pem=None):
        self.proof = proof
        self.private_key = private_key
        self.thumbprint = thumbprint
        self.alg = alg
        self.kid = kid
        self.jwk = jwk
        self.certificate_pem = certificate_pem
        self.tls_chain_pem = tls_chain_pem

    def private_pem(self) -> str:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")


def _unsigned(n: int) -> bytes:
    length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def jwk_thumbprint(jwk: dict) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        canonical = {"crv": jwk.get("crv"), "kty": "EC", "x": jwk.get("x"), "y": jwk.get("y")}
    elif kty == "RSA":
        canonical = {"e": jwk.get("e"), "kty": "RSA", "n": jwk.get("n")}
    elif kty == "OKP":
        canonical = {"crv": jwk.get("crv"), "kty": "OKP", "x": jwk.get("x")}
    else:
        raise GnapError("config", f"a {kty} key is not a GNAP client key this library loads")
    raw = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64url(hashlib.sha256(raw).digest())


def alg_of(jwk: dict) -> str:
    alg = jwk.get("alg")
    if isinstance(alg, str) and alg and alg != "none":
        return alg
    kty = jwk.get("kty")
    if kty == "EC":
        found = CURVE_ALG.get(jwk.get("crv") or "")
        if not found:
            raise GnapError("config", f"the curve {jwk.get('crv') or '(none)'} has no signature algorithm")
        return found
    if kty == "RSA":
        return "RS256"
    if kty == "OKP":
        return "EdDSA"
    raise GnapError("config", f"a {kty} key is not a GNAP client key this library loads")


def public_jwk_of(private_key) -> dict:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = {256: "P-256", 384: "P-384", 521: "P-521"}[private_key.curve.key_size]
        size = (private_key.curve.key_size + 7) // 8
        numbers = private_key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": curve,
            "x": b64url(numbers.x.to_bytes(size, "big")),
            "y": b64url(numbers.y.to_bytes(size, "big")),
        }
    elif isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": b64url(_unsigned(numbers.n)), "e": b64url(_unsigned(numbers.e))}
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
    else:
        raise GnapError("config", "a key of this type is not a GNAP client key this library loads")
    jwk["alg"] = alg_of(jwk)
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def public_key_from_jwk(jwk: dict):
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            n = int.from_bytes(b64url_decode_strict(jwk["n"]), "big")
            e = int.from_bytes(b64url_decode_strict(jwk["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            curve = CURVES[jwk["crv"]]
            x = int.from_bytes(b64url_decode_strict(jwk["x"]), "big")
            y = int.from_bytes(b64url_decode_strict(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        if kty == "OKP":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode_strict(jwk["x"]))
    except GnapError:
        raise
    except Exception as err:
        raise GnapError("signature", f"the key {jwk.get('kid') or ''} cannot be read: {err}", cause=err) from err
    raise GnapError("signature", f"the key {jwk.get('kid') or ''} cannot be read: unsupported {kty}")


def b64url_decode_strict(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value or ""):
        raise GnapError("signature", "the JWS part is not base64url")
    from .codec import b64url_decode
    return b64url_decode(value)


def public_key_object(key: ClientKey) -> dict:
    if key.proof == "mtls":
        if not key.certificate_pem:
            raise GnapError("config", "mutual TLS needs the client certificate")
        return {"proof": "mtls", "cert": key.certificate_pem.strip()}
    if not key.jwk:
        raise GnapError("config", f"{key.proof} needs a JWK")
    jwk = {"kty": key.jwk["kty"]}
    for name in ("crv", "x", "y", "n", "e"):
        if key.jwk.get(name):
            jwk[name] = key.jwk[name]
    jwk["alg"] = key.alg
    jwk["kid"] = key.kid
    return {"proof": key.proof, "jwk": jwk}


def sign_raw(key: ClientKey, data: bytes) -> bytes:
    alg = key.alg
    private_key = key.private_key
    if alg in ("EdDSA", "Ed25519"):
        return private_key.sign(data)
    digest = HASHES.get(alg)
    if digest is None:
        raise GnapError("config", f"this library does not sign with {alg}")
    if alg.startswith("ES"):
        der = private_key.sign(data, ec.ECDSA(digest))
        r, s = decode_dss_signature(der)
        size = (private_key.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    if alg.startswith("PS"):
        return private_key.sign(data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size))
    return private_key.sign(data, padding.PKCS1v15(), digest)


def verify_raw(public_key, alg: str, data: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        if alg in ("EdDSA", "Ed25519"):
            public_key.verify(signature, data)
            return True
        digest = HASHES.get(alg)
        if digest is None:
            return False
        if alg.startswith("ES"):
            size = len(signature) // 2
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(digest))
            return True
        if alg.startswith("PS"):
            public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size))
            return True
        public_key.verify(signature, data, padding.PKCS1v15(), digest)
        return True
    except Exception:
        return False


def spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate_blocks(pem: str) -> list:
    return CERT_RE.findall(pem or "")


def fingerprint256(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{byte:02X}" for byte in digest)


def load_client_key(private_key_pem: str, certificate_pem: str | None, proof: str | None) -> ClientKey:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception as err:
        raise GnapError("config", f"the private key could not be read: {err}", cause=err) from err
    jwk = public_jwk_of(private_key)
    certificate = None
    if certificate_pem:
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        except Exception as err:
            raise GnapError("config", f"the certificate could not be read: {err}", cause=err) from err
        if spki(private_key.public_key()) != spki(certificate.public_key()):
            raise GnapError("config", "the certificate is not the public half of the private key")
    chosen = proof or ("mtls" if certificate is not None else "httpsig")
    if chosen == "mtls" and certificate is None:
        raise GnapError("config", 'keyProof "mtls" needs certificate')
    if chosen == "mtls":
        blocks = certificate_blocks(certificate_pem or "")
        leaf = (blocks[0] if blocks else certificate_pem or "").strip() + "\n"
        chain_source = blocks if blocks else [certificate_pem or ""]
        tls_chain = "\n".join(block.strip() for block in chain_source) + "\n"
        # x5t#S256 is SHA-256 of the certificate DER.
        thumb = b64url(hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest())
        return ClientKey("mtls", private_key, thumb, jwk["alg"], jwk["kid"], jwk, leaf, tls_chain)
    return ClientKey(
        chosen, private_key, jwk["kid"], jwk["alg"], jwk["kid"], jwk,
        certificate_pem if certificate_pem else None, None,
    )
