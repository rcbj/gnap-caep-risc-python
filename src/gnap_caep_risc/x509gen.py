# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""A self-signed P-256 certificate for the client's mutual TLS key. Only key usage is digitalSignature."""

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .keys import fingerprint256


class KeyPair:
    def __init__(self, private_key_pem, certificate_pem, certificate, private_key):
        self.private_key_pem = private_key_pem
        self.certificate_pem = certificate_pem
        self.certificate = certificate
        self.private_key = private_key
        self.fingerprint256 = fingerprint256(certificate)


def create_self_signed_key_pair(common_name, days=1095, dns=None, ip=None) -> KeyPair:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)
    not_after = not_before + datetime.timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    alt = []
    for host in dns or []:
        alt.append(x509.DNSName(host))
    for address in ip or []:
        alt.append(x509.IPAddress(ipaddress.ip_address(address)))
    if alt:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    certificate = builder.sign(private_key, hashes.SHA256())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return KeyPair(private_pem, certificate_pem, certificate, private_key)
