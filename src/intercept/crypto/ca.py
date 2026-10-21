"""Certificate authority for TLS interception.

A single self signed root CA is created on first run. Leaf certificates are
generated on demand per hostname and cached, which keeps the handshake cost
off the hot path.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from intercept.core.protocols import ALPN_PROTOCOLS

__all__ = ["CertificateAuthority", "LeafCertificate"]

_ORG = "Intercept"
_VALID_DAYS = 3650
_LEAF_VALID_DAYS = 397


@dataclass(slots=True)
class LeafCertificate:
    hostname: str
    cert_path: Path
    key_path: Path
    not_after: dt.datetime

    @property
    def expired(self) -> bool:
        return self.not_after < dt.datetime.now(dt.UTC)


class CertificateAuthority:
    """Issues and caches certificates for intercepted hosts."""

    def __init__(
        self,
        home: Path | str | None = None,
        common_name: str = "Intercept Root CA",
        organization: str = _ORG,
        alpn: list[str] | None = None,
    ) -> None:
        from intercept.core.config import state_dir

        base = Path(home) if home else state_dir()
        self.dir = base / "ca"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.common_name = common_name
        self.organization = organization
        self.alpn = list(alpn) if alpn else list(ALPN_PROTOCOLS)
        self.root_cert_path = self.dir / "root.crt"
        self.root_key_path = self.dir / "root.key"
        self._leaves: dict[str, LeafCertificate] = {}
        self._contexts: dict[str, ssl.SSLContext] = {}
        # Re-entrant: ssl_context() calls leaf() while holding the lock.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ root

    def _generate_root(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        self.root_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.root_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def ensure_root(self) -> None:
        if not (self.root_cert_path.exists() and self.root_key_path.exists()):
            with self._lock:
                if not (self.root_cert_path.exists() and self.root_key_path.exists()):
                    self._generate_root()

    def root_certificate(self) -> x509.Certificate:
        self.ensure_root()
        return x509.load_pem_x509_certificate(self.root_cert_path.read_bytes())

    def root_key(self) -> rsa.RSAPrivateKey:
        self.ensure_root()
        key = serialization.load_pem_private_key(self.root_key_path.read_bytes(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        return key

    def root_pem(self) -> bytes:
        self.ensure_root()
        return self.root_cert_path.read_bytes()

    def fingerprint(self) -> str:
        cert = self.root_certificate()
        return cert.fingerprint(hashes.SHA256()).hex().upper()

    def subject(self) -> str:
        return self.root_certificate().subject.rfc4514_string()

    # ----------------------------------------------------------------- leaves

    def _build_leaf(self, hostname: str) -> LeafCertificate:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_key = self.root_key()
        root_cert = self.root_certificate()

        try:
            ip = ipaddress.ip_address(hostname)
            alt: x509.GeneralName = x509.IPAddress(ip)
        except ValueError:
            alt = x509.DNSName(hostname)

        now = dt.datetime.now(dt.UTC)
        not_after = now + dt.timedelta(days=_LEAF_VALID_DAYS)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]))
            .issuer_name(root_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(root_key, hashes.SHA256())
        )

        safe = hostname.replace("/", "_").replace(":", "_").replace("*", "_")
        cert_path = self.dir / f"{safe}.crt"
        key_path = self.dir / f"{safe}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return LeafCertificate(
            hostname=hostname,
            cert_path=cert_path,
            key_path=key_path,
            not_after=not_after,
        )

    def leaf(self, hostname: str) -> LeafCertificate:
        """Return a (cached) leaf certificate for *hostname*."""
        with self._lock:
            existing = self._leaves.get(hostname)
            if existing is not None and not existing.expired:
                return existing
            leaf = self._build_leaf(hostname)
            self._leaves[hostname] = leaf
            return leaf

    def ssl_context(self, hostname: str) -> ssl.SSLContext:
        """A server side TLS context presenting a certificate for *hostname*."""
        with self._lock:
            context = self._contexts.get(hostname)
            if context is not None:
                return context
            leaf = self.leaf(hostname)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
            context.set_alpn_protocols(list(self.alpn))
            self._contexts[hostname] = context
            return context

    def sni_context(self, on_name: Callable[[str], None] | None = None) -> ssl.SSLContext:
        """A TLS context that picks its certificate by the SNI the client sent.

        A transparent listener does not know the host name before the handshake
        starts, so the certificate has to be chosen while it is running. The
        name the client asked for is passed to *on_name* so the caller can
        reach the same host upstream.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_alpn_protocols(list(self.alpn))

        def callback(
            ssl_object: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext
        ) -> ssl.SSLContext | None:
            if not server_name:
                return None
            if on_name is not None:
                on_name(server_name)
            return self.ssl_context(server_name)

        context.sni_callback = callback
        return context

    def export(self, destination: Path | str | None = None) -> Path:
        """Write the root CA certificate to *destination* (default ``<home>/ca.crt``)."""
        target = Path(destination) if destination else self.dir.parent / "ca.crt"
        target.write_bytes(self.root_pem())
        return target
